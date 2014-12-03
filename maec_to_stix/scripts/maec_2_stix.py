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
# Updated 12/03/2014

import argparse
from maec_to_stix import __version__, wrap_maec_package, extract_indicators
from maec_to_stix.indicator_extractor import ConfigParser

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
    parser.add_argument("-infile","-i", help="the name of the input MAEC Package XML file.")
    parser.add_argument("-outfile","-o", help="the name of the output STIX Package XML file.")
    parser.add_argument("-config_file","-c", help="the path to the main Indicator extraction JSON configuration file.", default=None)
    opts_group = parser.add_mutually_exclusive_group()
    opts_group.add_argument("--wrap", "-w", help="wrap the input MAEC Package file in a STIX Package.", action="store_true", default=False)
    opts_group.add_argument("--extract", "-e", help="attempt to extract indicators from the MAEC Package and output them in a new STIX Package.", action="store_true", default=False)
    opts_group.add_argument("--print_options", "-p", help="print out the current set of indicator extraction options, including the supported Actions and Objects.", action="store_true", default=False)
    args = parser.parse_args()

    # Wrap the MAEC document in a STIX Package
    if args.wrap:
        stix_package = wrap_maec_package(args.infile)
        write_stix_package(stix_package, args.outfile)
    # Attempt to extract Indicators from the MAEC document
    elif args.extract:
        stix_package = extract_indicators(args.infile, args.config_file)
        if stix_package.indicators:
            write_stix_package(stix_package, args.outfile)
        else:
            print "No indicators were extracted. STIX Output file not created."
    # Print the Indicator extraction configuration options
    elif args.print_options:
        config_parser = ConfigParser(args.config_file)
        config_parser.print_config()
    else:
        parser.print_usage()

if __name__ == "__main__":
    main()    
