MAEC to STIX Examples
=====================

The following examples demonstrate the capabilities of **maec-to-stix**,
including the wrapping of MAEC Package data in a STIX Package, and also
the extraction of STIX Indicators from a MAEC Package.

stix_maec_wrapped.xml
------------------------

The ``stix_maec_wrapped.xml`` file is a STIX Package that demonstrates how
**maec-to-stix** was used to wrap a sample MAEC Package
(``maec_package_example.xml``) in STIX. It was generated using the following 
command:

.. code-block:: bash

    $ maec_2_stix.py -w -i maec_package_example.xml -o stix_maec_indicators.xml

stix_maec_indicators.xml
------------------------

The ``stix_maec_indicators.xml`` file is a STIX Package that demonstrates how
**maec-to-stix** was used to extract indicators from a sample MAEC Package
(``maec_package_example.xml``). It was generated using the following command:

.. code-block:: bash

    $ maec_2_stix.py -e -i maec_package_example.xml -o stix_maec_indicators.xml
	
