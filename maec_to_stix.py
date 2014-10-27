#***************************************************#
#                                                   #
#      MAEC -> STIX XML Converter Script            #
#                                                   #
# Copyright (c) 2014 - The MITRE Corporation        #
#                                                   #
#***************************************************#

# BY USING THE MAEC TO STIX SCRIPT, YOU SIGNIFY YOUR ACCEPTANCE OF THE TERMS AND 
# CONDITIONS OF USE.  IF YOU DO NOT AGREE TO THESE TERMS, DO NOT USE THE MAEC
# TO STIX SCRIPT.

# For more information, please refer to the LICENSE.txt file.

# MAEC to STIX Converter Script
# Copyright 2014, MITRE Corp
# v0.10 - BETA
# Updated 10/27/2014

import sys
import os
import traceback
import argparse
import maec
import stix.utils
from stix.core import STIXPackage, STIXHeader
from stix.common import InformationSource
from stix.ttp import TTP, Behavior
from stix.extensions.malware.maec_4_1_malware import MAECInstance
from cybox.common import ToolInformation, ToolInformationList
from lxml import etree

__version__ = 0.10

def wrap_maec(input_maec):
    '''Wrap a MAEC Package in a STIX TTP/Package.
       Return the newly created STIX Package.'''

    # Parse the input MAEC Package and get the API object
    maec_package = maec.parse_xml_instance(input_maec)['api']

    # Set the namespace to be used in the STIX Package
    stix.utils.set_id_namespace({"https://github.com/MAECProject/maec-to-stix":"MAECtoSTIX"})

    # Create the STIX MAEC Instance
    maec_malware_instance = MAECInstance()
    maec_malware_instance.maec = etree.fromstring(maec_package.to_xml(), parser=etree.ETCompatXMLParser())
    
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
    tool_info.version = str(__version__)
    stix_header.information_source.tools = ToolInformationList(tool_info)
    stix_package.stix_header = stix_header
    
    return stix_package

def main():
    # Setup the argument parser
    parser = argparse.ArgumentParser(description="MAEC to STIX " + str(__version__))
    parser.add_argument("input", help="the name of the input MAEC Package XML file.")
    parser.add_argument("output", help="the name of the output STIX Package XML file.")
    parser.add_argument("--wrap", "-w", help="wrap the input MAEC Package file in a STIX Package.", action="store_true", default=True)
    #parser.add_argument("--extract", "-e", help="attempt to extract indicators from the MAEC Package file and output them in a new STIX Package.", action="store_true", default=False)
    args = parser.parse_args()

    if args.wrap:
        stix_package = wrap_maec(args.input)
        out_file = open(args.output, "w")
        out_file.write(stix_package.to_xml())
        out_file.flush()
        out_file.close()

if __name__ == "__main__":
    main()    
