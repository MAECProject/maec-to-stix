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
# Updated 11/24/2014

import sys
import os
import traceback
import argparse
import json
import maec
from maec_to_stix import __version__
from maec_to_stix.stix_wrapper import wrap_maec
from maec_to_stix.indicator_extractor import IndicatorExtractor, ConfigParser

def write_stix_package(stix_package, output_file):
    """Write a STIX Package to an XML file."""
    try:
        stix_xml = stix_package.to_xml()
        out_file = open(output_file, "w")
        out_file.write("<?xml version='1.0' encoding='UTF-8'?>\n")
        out_file.write(stix_xml)
        out_file.flush()
        out_file.close()
    except Exception:
        raise

def main():
    # Setup the argument parser
    parser = argparse.ArgumentParser(description="MAEC to STIX " + str(__version__))
    parser.add_argument("-input","-i", help="the name of the input MAEC Package XML file.")
    parser.add_argument("-output","-o", help="the name of the output STIX Package XML file.")
    opts_group = parser.add_mutually_exclusive_group()
    opts_group.add_argument("--wrap", "-w", help="wrap the input MAEC Package file in a STIX Package.", action="store_true", default=False)
    opts_group.add_argument("--extract", "-e", help="attempt to extract indicators from the MAEC Package and output them in a new STIX Package.", action="store_true", default=False)
    opts_group.add_argument("--print_options", "-p", help="print out the current set of indicator extraction options, including the supported Actions and Objects.", action="store_true", default=False)
    args = parser.parse_args()

    # Parse the input MAEC Package
    if args.wrap or args.extract:
        maec_package = maec.parse_xml_instance(args.input)['api']

    # Wrap the MAEC document in a STIX Package
    if args.wrap:
        stix_package = wrap_maec(maec_package, args.input)
        write_stix_package(stix_package, args.output)
    # Attempt to extract Indicators from the MAEC document
    elif args.extract:
        extractor = IndicatorExtractor(maec_package, args.input)
        if extractor.stix_package.indicators:
            write_stix_package(extractor.stix_package, args.output)
        else:
            print "No indicators were extracted. STIX Output file not created."
    # Print the Indicator extraction configuration options
    elif args.print_extract_options:
        config_parser = ConfigParser()
        config_parser.print_config()
    else:
        print "Error: Unspecified mode. One of wrap (-w), indicator extraction (-e), or indicator extraction option printing (-p) modes must be specified."


if __name__ == "__main__":
    main()    
