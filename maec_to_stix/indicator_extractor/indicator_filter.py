import re
from config_parser import ConfigParser

class IndicatorFilter(object):
    def __init__(self, config):
        # The parsed configuration structure
        self.config = config
        # A list of action terms that indicate that the Object may no longer 
        # be present after the execution of the malware
        # E.g. that a particular file may be deleted
        self.contraindicators = ["delete", "kill"]
        # A list of action terms that indicate that the state of the Object
        # may have been changed in some way that would render it undetectable. 
        # Primarily applicable to files (?).
        self.modifiers = ["move", "copy", "rename"]

    def _contraindicator_check(self, object_history_entry):
        """Check an Object for Action-based contraindicators that may render it
           useless for detection. E.g., that the Object was created and later deleted."""
        object_id = object_history_entry.object.id_
        # Get the context with regards to the Actions that operated on the Object
        action_context = object_history_entry.get_action_context()
        contraindication = False
        for context_entry in action_context:
            if contraindication:
                break
            action_name = context_entry[0]
            association_type = context_entry[1]
            # Check for the contraindicators and modifiers
            if action_name and association_type:
                for contraind in self.contraindicators:
                    if contraind in action_name:
                        contraindication = True
                        break
                for modifier in self.modifiers:
                    if modifier in action_name and association_type == "input":
                        contraindication = True
                        break
        # Return the contraindication value
        return contraindication

    def _whitelist_test(self, element_value, whitelist):
        """Test an Object element value against a list of whitelisted values."""
        if whitelist:
            for whitelist_pattern in whitelist:
                if re.match(whitelist_pattern, str(element_value)):
                    return False
        return True

    def _prune_object_properties(self, object_dict, supported_properties, parent_key = None):
        """Prune any un-wanted properties from a single Object.
           Return a dictionary with only the allowed properties."""
        pruned_dict = {}
        for property_name, property_value in object_dict.items():
            if parent_key:
                updated_key = parent_key + "/" + property_name
            else:
                updated_key = property_name
            # Test if the value is a string or a number
            if isinstance(property_value, basestring) or hasattr(property_value, "__int__"):
                if not parent_key and property_name in supported_properties.keys():
                    # Test to make sure the element value doesn't match
                    # against any whitelisted values
                    if self._whitelist_test(property_value, supported_properties[property_name]):
                        pruned_dict[property_name] = property_value
                elif parent_key:
                    split_key = parent_key.split("/")
                    split_key.append(property_name)
                    for object_path in supported_properties.keys():
                        split_object_path = object_path.split("/")
                        # Test to make sure the root keys match
                        if split_key[0] == split_object_path[0]:
                            match = True
                            # Corner case for dealing with "value" keys
                            # that may appear in element dictionaries
                            if split_key[-1] == "value":
                                split_key.pop()
                            # Test to make sure the other path keys are 
                            # encompassed by the supported object path
                            for path_value in split_key[1:]:
                                if path_value not in split_object_path[1:]:
                                    match = False
                                    break
                            # Test to make sure the element value doesn't match
                            # against any whitelisted values
                            if match and self._whitelist_test(property_value, supported_properties[object_path]):
                            # Add the property key/value if everything matched
                                pruned_dict[property_name] = property_value
            # Test if the value is a dictionary
            elif isinstance(property_value, dict):
                pruned_nested_dict = {}
                pruned_nested_dict = self._prune_object_properties(property_value, supported_properties, updated_key)
                if pruned_nested_dict:
                    pruned_dict[property_name] = pruned_nested_dict
            # Test if the value is a list
            elif isinstance(property_value, list):
                pruned_list = []
                for list_item in property_value:
                    pruned_list.append(self._prune_object_properties(list_item, supported_properties, updated_key))
                if pruned_list and {} not in pruned_list:
                    pruned_dict[property_name] = pruned_list
        return pruned_dict

    def _required_property_check(self, object, object_properties_dict):
        """Check an Object to make sure it has the specified set of 
           required properties."""
        properties_found = True
        required_properties = object_properties_dict["required"]
        mutually_exclusive_properties = object_properties_dict["mutually_exclusive_required"]
        pruned_properties = self._prune_object_properties(object.properties.to_dict(), required_properties)
        # Check for the required properties
        if len(ConfigParser.flatten_dict(pruned_properties).keys()) != len(required_properties.keys()):
            properties_found = False
        # Check for the mutually exclusive required properties
        if mutually_exclusive_properties:
            mutually_exclusive_pruned = self._prune_object_properties(object.properties.to_dict(), mutually_exclusive_properties)
            if len(mutually_exclusive_pruned.keys()) != 1:
                properties_found = False
        return properties_found

    def prune_objects(self, candidate_indicator_objects):
        """Prune any un-wanted properties from the Candidate Indicator Objects.
           Also, deduplicate any identical Objects."""
        final_indicator_objects = []
        # Prune any unwanted properties from Objects
        for entry in candidate_indicator_objects:
            object = entry.object
            xsi_type = object.properties._XSI_TYPE
            # Do the contraindicator check
            if xsi_type in self.config.supported_objects and not self._contraindicator_check(entry):
                # Prune the properties of the Object to correspond to the input config file
                # First, test for the presence of only the required properties
                if self._required_property_check(object, self.config.supported_objects[xsi_type]):
                    # If the required properties are found, prune based on the full set (optional + required)
                    full_properties = {}
                    full_properties.update(self.config.supported_objects[xsi_type]["required"])
                    full_properties.update(self.config.supported_objects[xsi_type]["optional"])
                    full_properties.update(self.config.supported_objects[xsi_type]["mutually_exclusive_required"])
                    full_pruned_properties = self._prune_object_properties(object.properties.to_dict(), full_properties)
                    full_pruned_properties["xsi:type"] = xsi_type
                    # Create a new Object with the pruned ObjectProperties
                    pruned_object = Object()
                    pruned_object.properties = ObjectProperties.from_dict(full_pruned_properties)
                    entry.object = pruned_object
                    # Add the updated Object History entry to the final list of Indicators
                    final_indicator_objects.append(entry)
        return final_indicator_objects
