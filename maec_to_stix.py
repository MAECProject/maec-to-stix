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
# Updated 10/31/2014

import sys
import os
import traceback
import argparse
import json
from maec_to_stix.stix_wrapper import wrap_maec
from maec_to_stix.indicator_extractor import IndicatorExtractor

__version__ = 0.10

def main():
    # Setup the argument parser
    parser = argparse.ArgumentParser(description="MAEC to STIX " + str(__version__))
    parser.add_argument("input", help="the name of the input MAEC Package XML file.")
    parser.add_argument("output", help="the name of the output STIX Package XML file.")
    opts_group = parser.add_mutually_exclusive_group()
    opts_group.add_argument("--wrap", "-w", help="wrap the input MAEC Package file in a STIX Package.", action="store_true", default=False)
    opts_group.add_argument("--extract", "-e", help="attempt to extract indicators from the MAEC Package file and output them in a new STIX Package.", action="store_true", default=False)
    args = parser.parse_args()

    # Wrap the MAEC document in a STIX Package
    if args.wrap:
        stix_package = wrap_maec(args.input, __version__)
    # Attempt to extract Indicators from the MAEC document
    if args.extract:
        # Parse and load the JSON config structure
        with open('extractor_config.json', mode='r') as f:
            extractor_config = json.loads(f.read())
        extractor = IndicatorExtractor(args.input, extractor_config, __version__)
        stix_package = extractor.create_stix()

    # Write out the STIX Package to an XML file
    out_file = open(args.output, "w")
    out_file.write(stix_package.to_xml())
    out_file.flush()
    out_file.close()


if __name__ == "__main__":
    main()    
