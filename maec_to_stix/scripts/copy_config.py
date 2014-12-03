# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.
# MAEC to STIX configuration copying script

import shutil
import os
import sys
import argparse
from pkg_resources import resource_filename

def main():
    # Setup the argument parser
    parser = argparse.ArgumentParser(description="MAEC to STIX configuration copying script")
    parser.add_argument("outpath", help="""the output directory into which to copy the MAEC to STIX Indicator extraction configuration files. 
                                           If the directory does not already exist, it will be created by the script.""")
    args = parser.parse_args()

    # Create the output directory if it does not exist
    if not os.path.exists(args.outpath):
        os.makedirs(args.outpath)

    # Get the path to the Indicator extraction configuration files
    config_path = resource_filename("maec_to_stix", "indicator_extractor/config")

    sys.stdout.write("Copying configuration files")
    for config_file in os.listdir(config_path):
        # Copy the Indicator Extractor configuration files to the output directory
        shutil.copy2(os.path.join(config_path,config_file), os.path.join(args.outpath,config_file))
        sys.stdout.write(".")
    sys.stdout.write("Done\n")

if __name__ == "__main__":
    main()    