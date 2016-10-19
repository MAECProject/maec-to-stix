#!/usr/bin/env python

# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import sys
import warnings
import argparse
from maec_to_stix import __version__, wrap_maec_package

def write_stix_package(stix_package, output_file):
    """Write a STIX Package to an XML file."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        stix_xml = stix_package.to_xml()
        warnings.resetwarnings()
    if isinstance(output_file, basestring):
        out_file = open(output_file, "w")
    else:
        out_file = output_file
    out_file.write("<?xml version='1.0' encoding='UTF-8'?>\n")
    out_file.write(stix_xml)
    out_file.flush()
    out_file.close()

def main():
    # Setup the argument parser
    parser = argparse.ArgumentParser(description="MAEC to STIX Wrapper Script v" + str(__version__))
    parser.add_argument("infile", help="the name of the input MAEC Package XML file to wrap in STIX.")
    parser.add_argument("--outfile", "-o", help="the name of the output STIX Package XML file. If not specified, defaults to sys.stdout.", default=sys.stdout)
    args = parser.parse_args()

    # Wrap the MAEC document in a STIX Package
    stix_package = wrap_maec_package(args.infile)
    write_stix_package(stix_package, args.outfile)

if __name__ == "__main__":
    main()    
