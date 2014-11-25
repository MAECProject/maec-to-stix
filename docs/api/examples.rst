Example Code
============

The following sections demonstrate how to use the **maec-to-stix** library to
wrap MAEC content in STIX and also extract STIX Indicators from MAEC.
For more details about the **maec-to-stix**** API, see the :doc:`/api/index` page.

Import maec-to-stix
^^^^^^^^^^^^^^^^^^^

To use **maec-to-stix** for wrapping MAEC in STIX and extracting STIX Indicators, 
you must import the ``maec-to-stix`` module. There are lots of functions, classes, and 
submodules under ``maec-to-stix``, but the top-level module is all you need for most usage.

.. code-block:: python

    import maec_to_stix  # That's it!

Wrapping MAEC Content in STIX
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Wrapping MAEC content with **maec-to-stix** is simple - once the imports are 
taken care of, you only need to call the :meth:`maec_to_stix.wrap_maec_package` method, 
which parses the input MAEC Package, wraps it in STIX, and returns an instance of a
`stix.STIXPackage` class (from the **python-stix** API) with the wrapped MAEC content.

.. code-block:: python

    import maec_to_stix

    # Wrap the 'sample_maec_package.xml' MAEC document in a STIX Package
    stix_package = maec_to_stix.wrap_maec_package('sample_maec_package.xml')

.. note::

    The :meth:`maec_to_stix.wrap_maec_package` method expects a filename to be passed in.
	For passing in `maec.Package` objects directly, please see the :doc:`/api/stix_wrapper/index` 
	page.

Extracting STIX Indicators from MAEC Content
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Extracting STIX Indicators from MAEC content with **maec-to-stix** is equally simple - 
once the imports are taken care of, you only need to call the 
:meth:`maec_to_stix.extract_indicators` method, which parses the input MAEC Package, 
attempts to extract STIX Indicators from it, and returns an instance of a 
`stix.STIXPackage` class (from the **python-stix** API) with the extracted Indicators.

.. code-block:: python

    import maec_to_stix

    # Extract STIX Indicators from the 'sample_maec_package.xml' MAEC document
    stix_package = maec_to_stix.extract_indicators('sample_maec_package.xml')

.. note::

    The :meth:`maec_to_stix.extract_indicators` method expects a filename to be passed in.
	For passing in `maec.Package` objects directly, please see the :doc:`/api/indicator_extractor/index` 
	page.
