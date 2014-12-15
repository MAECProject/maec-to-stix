# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import warnings
import argparse
from maec_to_stix import (__version__, extract_indicators,
                          _custom_formatwarning)
from maec_to_stix.indicator_extractor import ConfigParser

def write_stix_package(stix_package, output_file):
    """Write a STIX Package to an XML file."""
    stix_xml = stix_package.to_xml()
    out_file = open(output_file, "w")
    out_file.write("<?xml version='1.0' encoding='UTF-8'?>\n")
    out_file.write(stix_xml)
    out_file.flush()
    out_file.close()

def main():
    # Setup the argument parser
    parser = argparse.ArgumentParser(description="MAEC to STIX Indicator Extraction Script v" + str(__version__))
    parser.add_argument("infile", help="the name of the input MAEC Package XML file to extract indicators from.")
    parser.add_argument("outfile", help="the name of the output STIX Package XML file.")
    parser.add_argument("--config_directory","-c", help="the path to the directory housing the Indicator extraction JSON configuration files.", default=None)
    parser.add_argument("--print_options", "-p", help="print out the current set of indicator extraction options, including the supported Actions and Objects.", action="store_true", default=False)
    args = parser.parse_args()

    # Print the Indicator extraction configuration options
    if args.print_options:
        config_parser = ConfigParser(args.config_directory)
        config_parser.print_config()
    # Attempt to extract Indicators from the MAEC document
    elif args.infile and args.outfile:
        stix_package = extract_indicators(args.infile, args.config_directory)
        if stix_package:
            write_stix_package(stix_package, args.outfile)
        else:
            warnings.formatwarning = _custom_formatwarning
            warnings.warn("No STIX Package created.", UserWarning)
    else:
        parser.print_usage()

if __name__ == "__main__":
    main()    
