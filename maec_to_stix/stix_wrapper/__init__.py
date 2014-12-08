# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import maec
import stix.utils
import maec_to_stix
from stix.core import STIXPackage, STIXHeader
from stix.common import InformationSource
from stix.ttp import TTP, Behavior
from stix.extensions.malware.maec_4_1_malware import MAECInstance
from cybox.common import ToolInformation, ToolInformationList
from lxml import etree

def wrap_maec(maec_package, file_name=None):
    """Wrap a MAEC Package in a STIX TTP/Package. Return the newly created STIX Package.

    Args:
        maec_package: the ``maec.package.package.Package`` instance to wrap in STIX.
        file_name: the name of the input file from which the MAEC Package originated,
            to be used in the Title of the STIX TTP that wraps the MAEC Package. Optional.

    Returns:
        A ``stix.STIXPackage`` instance with a single TTP that wraps the input MAEC Package.
    """

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
    if file_name:
        stix_header.title = "STIX TTP wrapper around MAEC file: " + str(file_name)
    stix_header.add_package_intent("Malware Characterization")
    # Add the Information Source to the STIX Header
    tool_info = ToolInformation()
    stix_header.information_source = InformationSource()
    tool_info.name = "MAEC to STIX"
    tool_info.version = str(maec_to_stix.__version__)
    stix_header.information_source.tools = ToolInformationList(tool_info)
    stix_package.stix_header = stix_header
    
    return stix_package