# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

__version__ = "1.0.0-alpha1"

import maec
from stix_wrapper import wrap_maec
from indicator_extractor import IndicatorExtractor

def wrap_maec_package(package_filename):
    """Wrap a MAEC Package file in a STIX Package/TTP.
    
    Args:
        package_filename: The name of the MAEC Package file to wrap.

    Returns:
        A ``stix.STIXPackage`` instance with the wrapped MAEC data.
    
    """
    # Parse the input MAEC Package
    maec_package = maec.parse_xml_instance(package_filename)['api']

    # Wrap the MAEC Package in STIX
    stix_package = wrap_maec(maec_package, package_filename)

    return stix_package

def extract_indicators(package_filename, config_file=None):
    """Extract STIX Indicators from a MAEC Package file.
    
    Args:
        package_filename: The name of the MAEC Package file to extract indicators from.
        config_file: (optional) The path to the indicator extraction configuration file
            (typically 'extractor_config.json') to be used for configuring the behavior
            of the Indicator extraction. 

    Returns:
        A ``stix.STIXPackage`` instance with the extracted STIX Indicators.
    
    """
    # Parse the input MAEC Package
    maec_package = maec.parse_xml_instance(package_filename)['api']

    # Extract the STIX Indicators from the MAEC Package
    indicator_extractor = IndicatorExtractor(maec_package, package_filename, config_file)
    
    return indicator_extractor.stix_package