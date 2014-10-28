# MAEC to STIX
# Wrapper methods
import maec
import stix.utils
from stix.core import STIXPackage, STIXHeader
from stix.common import InformationSource
from stix.ttp import TTP, Behavior
from stix.extensions.malware.maec_4_1_malware import MAECInstance
from cybox.common import ToolInformation, ToolInformationList
from lxml import etree

def wrap_maec(input_maec, version):
    '''Wrap a MAEC Package in a STIX TTP/Package.
       Return the newly created STIX Package.'''

    # Parse the input MAEC Package and get the API object
    maec_package = maec.parse_xml_instance(input_maec)['api']

    # Set the namespace to be used in the STIX Package
    stix.utils.set_id_namespace({"https://github.com/MAECProject/maec-to-stix":"MAECtoSTIX"})

    # Create the STIX MAEC Instance
    maec_malware_instance = MAECInstance()
    maec_malware_instance.maec = maec_package
    
    # Create the STIX TTP that includes the MAEC Instance
    ttp = TTP()
    ttp.behavior = Behavior()
    ttp.behavior.add_malware_instance(maec_malware_instance)
    
    # Create the STIX Package and add the TTP to it
    stix_package = STIXPackage()
    stix_package.add_ttp(ttp)

    # Create the STIX Header and add it to the Package
    stix_header = STIXHeader()
    stix_header.title = "STIX TTP wrapper around MAEC file: " + str(input_maec)
    stix_header.add_package_intent("Malware Characterization")
    # Add the Information Source to the STIX Header
    tool_info = ToolInformation()
    stix_header.information_source = InformationSource()
    tool_info.name = "MAEC to STIX"
    tool_info.version = str(version)
    stix_header.information_source.tools = ToolInformationList(tool_info)
    stix_package.stix_header = stix_header
    
    return stix_package