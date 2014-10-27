maec-to-stix
============
A python tool used to wrap or convert MAEC Packages to STIX Packages.

## Dependencies
The MAEC to STIX Utility has the following dependencies:
* python-maec >= v4.1.0.8: https://pypi.python.org/pypi/maec
* python-stix >= v1.1.1.2: https://pypi.python.org/pypi/stix
* python-cybox >= v2.1.0.8: https://pypi.python.org/pypi/cybox

## Use
The MAEC to STIX Utility can be used to wrap a MAEC Package in STIX. 
Specifically, the utility takes as input a MAEC Package XML file,
and outputs a STIX Package XML file with the MAEC Package wrapped
as a STIX TTP.

There are two positional command-line parameters:
* input : the name of the input MAEC Package XML file to wrap
* output : the name of the output STIX Package XML to write to

Example usage:
`maec_to_stix.py maec_package_file.xml stix_package_xml.file`

## Terms
BY USING THE MAEC TO STIX UTILITY, YOU SIGNIFY YOUR ACCEPTANCE OF THE 
TERMS AND CONDITIONS OF USE.  IF YOU DO NOT AGREE TO THESE TERMS, DO NOT USE 
THE STIX DOCUMENT VALIDATOR.

For more information, please refer to the LICENSE.txt file