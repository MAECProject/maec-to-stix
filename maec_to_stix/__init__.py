# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

__version__ = "1.0.0-alpha1"

import os
import maec
from maec_to_stix.stix_wrapper import wrap_maec
from maec_to_stix.indicator_extractor import IndicatorExtractor

def _custom_formatwarning(msg, *a):
    """Print a custom-formatted warning message."""
    # Ignore everything except the message
    return "Warning: " + str(msg) + '\n'

def wrap_maec_package(package):
    """Wrap a MAEC Package file in a STIX Package/TTP.
    
    Args:
        package: The MAEC Package file or file-like object to wrap.

    Returns:
        A ``stix.STIXPackage`` instance with the wrapped MAEC data.
    
    """
    # Parse the input MAEC Package
    maec_package = maec.parse_xml_instance(package)['api']

    # Test if the MAEC Package is a filename or not
    package_filename = None
    if isinstance(package, basestring) and os.path.isfile(package):
        package_filename = package

    # Wrap the MAEC Package in STIX
    stix_package = wrap_maec(maec_package, package_filename)

    return stix_package

def extract_indicators(package, config_directory=None):
    """Extract STIX Indicators from a MAEC Package file.
    
    Args:
        package: The MAEC Package file or file-like object to wrap.
        config_directory: (optional) The path to the directory housing the indicator 
            extraction configuration files. 

    Returns:
        If indicators were extracted, a ``stix.STIXPackage`` instance with the 
        extracted STIX Indicators. Otherwise, if no indicators were extracted,
        ``None``.
    
    """
    # Parse the input MAEC Package
    maec_package = maec.parse_xml_instance(package)['api']

    # Test if the MAEC Package is a filename or not
    package_filename = None
    if isinstance(package, basestring) and os.path.isfile(package):
        package_filename = package

    # Extract the STIX Indicators from the MAEC Package
    indicator_extractor = IndicatorExtractor(maec_package, package_filename, config_directory)

    return indicator_extractor.extract()