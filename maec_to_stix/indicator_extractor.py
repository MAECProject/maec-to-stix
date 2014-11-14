# MAEC Indicator Extractor Classes
# For extracting Indicators from MAEC data

import json
import os
import collections
import maec
from maec.package.package import Package
from maec.package.malware_subject import MalwareSubject
from maec.bundle.bundle import Bundle, ObjectList
from maec.bundle.object_history import ObjectHistory
import cybox.utils
from cybox.core import Object
from cybox.common import (ObjectProperties, ToolInformation, 
                          ToolInformation, ToolInformationList)
import stix.utils
from stix.core import STIXHeader, STIXPackage
from stix.common import Confidence, InformationSource
from stix.indicator import Indicator
from stix.ttp import TTP, Behavior
from stix.extensions.malware.maec_4_1_malware import MAECInstance

class IndicatorExtractor(object):
    def __init__(self, input_file, config, version):
        # The input MAEC Package file
        self.input_file = input_file
        # The output STIX Package (with Indicators)
        self.stix_package = None
        # JSON configuration blob
        self.config = config
        # Tool version
        self.version = version
        # List of supported Actions
        self.supported_actions = []
        # Dictionary of supported Objects and their properties
        self.supported_objects = {}
        # Set the STIX namsespace and alias
        stix.utils.set_id_namespace({'https://github.com/MAECProject/maec-to-stix' : 'maecToSTIX'})
        # Set the CybOX namespace and alias
        cybox.utils.set_id_namespace(cybox.utils.Namespace('https://github.com/MAECProject/maec-to-stix' , 'maecToSTIX'))
        # Set the MAEC namespace and alias
        maec.utils.set_id_namespace(cybox.utils.Namespace('https://github.com/MAECProject/maec-to-stix' , 'maecToSTIX'))
        # Parse the config structure
        self.parse_config()
        # Parse the MAEC Package 
        self.parse_package()

    def add_stix_ttp(self, malware_subject):
        """Create and add a STIX TTP for a MAEC Malware Subject."""
        # Create the STIX TTP that includes the MAEC Instance
        ttp = TTP()
        ttp.behavior = Behavior()
        # Add a MAEC Package with just the Malware Subject
        # For capturing the identity of the malware binary that the Indicators target
        maec_package = Package()
        new_malware_subject = MalwareSubject()
        new_malware_subject.malware_instance_object_attributes = malware_subject.malware_instance_object_attributes
        maec_package.add_malware_subject(new_malware_subject)
        maec_malware_instance = MAECInstance()
        maec_malware_instance.maec = maec_package
        ttp.behavior.add_malware_instance(maec_malware_instance)
        self.stix_package.add_ttp(ttp)
        return ttp.id_

    def add_stix_indicators(self, final_indicator_objects, ttp_id):
        """Create and add STIX Indicators for a list of Object History entries.
           Link each Indicator to their Indicated TTP."""
        for entry in final_indicator_objects:
            object = entry.object
            indicator = Indicator()
            indicator.title = "Malware Artifact Extracted from MAEC Document"
            indicator.add_indicator_type("Malware Artifacts")
            indicator.add_observable(object.properties)
            # Add the Action-derived description to the Indicator
            description = "Corresponding Action(s): "
            for action_name in entry.get_action_names():
                description += (action_name + ", ")
            indicator.description = description[:-2]
            # Set the proper Confidence on the Indicator
            confidence = Confidence()
            confidence.value = "Low"
            confidence.description = "Tool-generated Indicator. It is HIGHLY recommended that it be vetted by a human analyst before usage."
            indicator.confidence = confidence
            # Link the Indicator to its Indicated TTP
            ttp = TTP(idref=ttp_id)
            indicator.add_indicated_ttp(ttp)
            # Add the Indicator to the STIX Package
            self.stix_package.add_indicator(indicator)
        
    def create_stix_package(self):
        """Create and return a STIX Package with the final Indicator Objects."""
        stix_package = STIXPackage()
        stix_header = STIXHeader()
        stix_header.add_package_intent("Indicators - Malware Artifacts")
        stix_header.title = "STIX Indicators extracted from MAEC file: " + str(self.input_file)
        # Add the Information Source to the STIX Header
        tool_info = ToolInformation()
        stix_header.information_source = InformationSource()
        tool_info.name = "MAEC to STIX"
        tool_info.version = str(self.version)
        stix_header.information_source.tools = ToolInformationList(tool_info)
        stix_package.stix_header = stix_header
        return stix_package

    def set_object_property(self, property, condition = "Equals"):
        """Add a condition to an Object property and all of its children."""
        if isinstance(property, basestring) or hasattr(property, "__int__"):
            property = {'value':property, 'condition':condition}
        elif isinstance(property, dict):
            if 'condition' not in property:
                for key, value in property.items():
                    property[key] = self.set_object_property(value, condition)
        elif isinstance(property, list):
            for item in property:
                self.set_object_property(item, condition)
        return property

    def prepare_objects(self, final_indicator_objects):
        """Prepare the final Indicator Objects for translation into STIX Indicators.
           Set their condition attributes as appropriate."""
        for entry in final_indicator_objects:
            object = entry.object
            object_xsi_type = object.properties._XSI_TYPE
            object_properties_dict = object.properties.to_dict()
            updated_properties_dict = {}
            for property_name, property_value in object_properties_dict.items():
                updated_properties_dict[property_name] = self.set_object_property(property_value)
            updated_properties_dict['xsi:type'] = object_xsi_type
            object.properties = ObjectProperties.from_dict(updated_properties_dict)

    def contraindicator_check(self, object_history_entry):
        """Check an Object for Action-based contraindicators that may render it
           useless for detection. E.g., that the Object was created and later deleted."""
        # A list of action terms that indicate that the Object may no longer 
        # be present after the execution of the malware
        # E.g. that a particular file may be deleted
        contraindicators = ["delete", "kill"]
        # A list of action terms that indicate that the state of the Object
        # may have been changed in some way that would render it undetectable. 
        # Primarily applicable to files (?).
        modifiers = ["move", "copy", "rename"]
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
                for contraind in contraindicators:
                    if contraind in action_name:
                        contraindication = True
                        break
                for modifier in modifiers:
                    if modifier in action_name and association_type == "input":
                        contraindication = True
                        break
        # Return the contraindication value
        return contraindication

    def prune_object_properties(self, object_dict, supported_properties, parent_key = None):
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
                if not parent_key and property_name in supported_properties:
                    pruned_dict[property_name] = property_value
                elif parent_key:
                    split_key = parent_key.split("/")
                    split_key.append(property_name)
                    for object_path in supported_properties:
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
                            # Add the property key/value if everything matched
                            if match:
                                pruned_dict[property_name] = property_value
            # Test if the value is a dictionary
            elif isinstance(property_value, dict):
                pruned_nested_dict = {}
                pruned_nested_dict = self.prune_object_properties(property_value, supported_properties, updated_key)
                if pruned_nested_dict:
                    pruned_dict[property_name] = pruned_nested_dict
            # Test if the value is a list
            elif isinstance(property_value, list):
                pruned_list = []
                for list_item in property_value:
                    pruned_list.append(self.prune_object_properties(list_item, supported_properties, updated_key))
                if pruned_list:
                    pruned_dict[property_name] = pruned_list
        return pruned_dict

    def prune_objects(self, candidate_indicator_objects):
        """Prune any un-wanted properties from the Candidate Indicator Objects.
           Also, deduplicate any identical Objects."""
        final_indicator_objects = []
        # Prune any unwanted properties from Objects
        for entry in candidate_indicator_objects:
            object = entry.object
            xsi_type = object.properties._XSI_TYPE
            # Do the contraindicator check
            if xsi_type in self.supported_objects and not self.contraindicator_check(entry):
                # Prune the properties of the Object to correspond to the input config file
                pruned_properties = self.prune_object_properties(object.properties.to_dict(), self.supported_objects[xsi_type])
                if pruned_properties:
                    pruned_properties["xsi:type"] = xsi_type
                    # Create a new Object with the pruned ObjectProperties
                    pruned_object = Object()
                    pruned_object.properties = ObjectProperties.from_dict(pruned_properties)
                    entry.object = pruned_object
                    # Add the updated Object History entry to the final list of Indicators
                    final_indicator_objects.append(entry)
        return final_indicator_objects

    def flatten_dict(self, d, parent_key='', sep='/'):
        """Flatten an input dictionary."""
        items = []
        for k, v in d.items():
            new_key = parent_key + sep + k if parent_key else k
            if isinstance(v, collections.MutableMapping):
                items.extend(self.flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                for list_item in v:
                    items.extend(self.flatten_dict(list_item, new_key, sep=sep).items())
            else:
                items.append((new_key, v))
        return dict(items)

    def parse_object_config_dict(self, object_type, config_dict):
        """Parse an Object configuration dictionary."""
        flattened_dict = self.flatten_dict(config_dict)
        for key, value in flattened_dict.items():
            if value:
                if object_type not in self.supported_objects:
                    self.supported_objects[object_type] = [key]
                else:
                    self.supported_objects[object_type].append(key)

    def parse_granular_config(self, granular_config_file):
        """Parse a granular JSON configuration structure."""
        try:
            with open(os.path.join("config",granular_config_file), mode='r') as f:
                config = json.loads(f.read())
        except EnvironmentError:
            pass
        for config_type, config_values in config.items():
            if config_type == "supported objects":
                for object_type, properties_dict in config_values.items():
                    self.parse_object_config_dict(object_type, properties_dict)
            elif config_type == "supported actions":
                for enum_name, actions_dict in config_values.items():
                    for action_name, enabled in actions_dict.items():
                        if enabled:
                            self.supported_actions.append(action_name)

    def parse_config(self):
        """Parse and break up the JSON configuration structure."""
        # Use the granular options structure if specified
        if self.config["use_granular_options"]:
            self.parse_granular_config("granular_config.json")
        else:
            abstracted_options = self.config["abstracted_options"]
            for option, enabled in abstracted_options.items():
                if option == "file_system_activity" and enabled:
                    self.parse_granular_config("file_system_activity_config.json")
                elif option == "registry_activity" and enabled:
                    self.parse_granular_config("registry_activity_config.json")
                elif option == "mutex_activity" and enabled:
                    self.parse_granular_config("mutex_activity_config.json")           
                elif option == "process_activity" and enabled:
                    self.parse_granular_config("process_activity_config.json")
                elif option == "service_activity" and enabled:
                    self.parse_granular_config("service_activity_config.json")
                elif option == "network_activity" and enabled:
                    self.parse_granular_config("network_activity_config.json")
                elif option == "driver_activity" and enabled:
                    self.parse_granular_config("driver_activity_config.json")

    def parse_package(self):
        """Parse a MAEC Package."""
        maec_package = maec.parse_xml_instance(self.input_file)['api']
        if maec_package.malware_subjects:
            for malware_subject in maec_package.malware_subjects:
                self.parse_malware_subject(malware_subject)

    def parse_object_history(self, object_history):
        """Parse the Object History to build the list of
           candidate Objects for use in Indicators."""
        candidate_indicator_objects = []
        for entry in object_history.entries:
            object_id = entry.object.id_
            # Get the context with regards to the Actions that operated on the Object
            action_context = entry.get_action_context()
            action_match = False
            # First, test if one of the supported Actions operated on the Object
            for context_entry in action_context:
                if context_entry[0] in self.supported_actions:
                    action_match = True
                    break
            # If a supported Action was found, add the Object to the list of candidates
            if action_match:
                candidate_indicator_objects.append(entry)
        return candidate_indicator_objects

    def create_bundle_indicators(self, object_history, ttp_id):
        """Create an add Indicators derived from a MAEC Bundle."""
        # Parse the object history to build the list of candidate Objects
        candidate_indicator_objects = self.parse_object_history(object_history)
        # Prune the candidate objects
        pruned_indicator_objects = self.prune_objects(candidate_indicator_objects)
        # Prepare the candidate objects for Indicatorization (TM)
        self.prepare_objects(pruned_indicator_objects)
        # Create and add the STIX Indicators for each of the final candidate indicator Objects
        self.add_stix_indicators(pruned_indicator_objects, ttp_id)

    def parse_bundle(self, bundle, ttp_id):
        """Parse a MAEC Bundle."""
        # Deduplicate the Objects in the Bundle
        bundle.deduplicate()
        # Build the Object history for the Bundle
        object_history = ObjectHistory()
        object_history.build(bundle)
        # Create the actual Indicators derived from the Bundle
        self.create_bundle_indicators(object_history, ttp_id)

    def parse_malware_subject(self, malware_subject):
        """Parse a MAEC Malware Subject."""
        # Parse the Findings Bundles in the Malware Subject
        if malware_subject.findings_bundles and malware_subject.findings_bundles.bundle:
            # Create the STIX Package if it does not exist yet
            if not self.stix_package:
                self.stix_package = self.create_stix_package()
            # Create and add the STIX TTP for the Malware Subject
            ttp_id = self.add_stix_ttp(malware_subject)
            for bundle in malware_subject.findings_bundles.bundle:
                self.parse_bundle(bundle, ttp_id)
