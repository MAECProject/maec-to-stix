Indicator Extraction Configuration Files
========================================
This page describes the location and usage of the indicator extraction
configuration files. For details on the structures of the files and their 
parameters please refer to the :doc:`high_level_config` or :doc:`granular_config`
pages.

Overview
--------
There are multiple configuration files - a main configuration file, one each 
for the different types of system activity included by default, and one granular
configuration file that contains the full list of MAEC Actions and CybOX Objects: 

================================= ========================================== ===========================
 File                              Description                                   Reference
================================= ========================================== ===========================
extractor_config.json               The main configuration file.              :doc:`high_level_config`
driver_activity_config.json         System activity configuration file.       :doc:`granular_config` 
file_system_activity_config.json    System activity configuration file.       :doc:`granular_config`
mutex_activity_config.json          System activity configuration file.       :doc:`granular_config`
network_activity_config.json        System activity configuration file.       :doc:`granular_config`
process_activity_config.json        System activity configuration file.       :doc:`granular_config`
registry_activity_config.json       System activity configuration file.       :doc:`granular_config`
service_activity_config.json        System activity configuration file.       :doc:`granular_config`
granular_config.json                Full granular configuration file.         :doc:`granular_config`                 
================================= ========================================== ===========================
 
Main Configuration File
~~~~~~~~~~~~~~~~~~~~~~~
 
The main configuration file is the driver of indicator extraction behavior
and is the first file parsed by the utility for this purpose. As such, it is
either automatically parsed by the utility from the **maec-to-stix**
installation directory, or passed in by the user. More information on this
can be found in the section below.
 
System Activity Configuration Files
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 
Each of the system activity configuration files contains only the set of MAEC 
Actions and CybOX Objects that are relevant in the context of the particular type
of system activity that it refers to. Note that not all of these Actions and CybOX
Objects and their properties are enabled in each activity-level configuration file 
by default; please see :doc:`granular_config_defaults` for the list of default 
Actions and CybOX Objects in each. Thus, each of these files may be edited for more
granular control of a particular system activity for which to extract indicators for.

Full Granular Configuration File
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
If one wishes to have even more control, there is a single "full" 
granular configuration file that represents the FULL list of possible MAEC 
Actions and CybOX Objects that may be configured for use in indicator extraction. 
This file is only used by the utility if the ``use_granular_options`` parameter in 
the :doc:`high_level_config` is set to **true**. Note that usage of this file 
is mutually exclusive with usage of the system-level activity configuration files.

Installation and Usage
-----------------------------
By default, the configuration files are installed in the **maec-to-stix** 
installation directory in ``python/lib/site-packages``. However, instead of
editing them in place there, we recommend copying them over to another directory
and making any changes as needed to these copies. To that end, we've provided
a script, ``copy_maec_to_stix_config.py``, that will copy all of the configuration
files to a user-specified directory. For more information on this script, please 
refer to :ref:`copy-config`.

Accordingly, in order to use any user-edited files, the utility needs to be told
where to find them. Luckily, this is a very simple process, for both the 
``maec_extract_indicators.py`` script, as well as the API.

maec_extract_indicators.py
~~~~~~~~~~~~~~
``maec_extract_indicators.py`` includes a *-config_directory* (or *-c*)
command-line parameter for specifying the directory where the configuration 
files are located. 

Example
^^^^^^^
As an example, let's assume that we've edited the main configuration file
and some of the granular configuration files and placed them in ``/usr/tmp``.
The following command-line would force ``maec_extract_indicators.py`` to use
these modified configuration files:

.. code-block:: bash

    $ maec_extract_indicators.py -config_file /usr/tmp -infile maec_doc.xml -outfile stix_doc.xml

API
~~~
The **maec-to-stix** API supports passing in the path to the directory where the
configuration files are stored through the **config_directory** parameter in 
:meth:`maec_to_stix.extract_indicators`. **NOTE**: this assumes that the 
granular configuration files are located in the same directory as the main 
configuration file.

Example
^^^^^^^
As an example, let's assume that we've edited the main configuration file
and some of the granular configuration files and placed them in ``/usr/tmp``.
The following **maec-to-stix** API usage demonstrates how these modified
configuration files would be passed in:

.. code-block:: python

    import maec_to_stix

    # Extract STIX Indicators from the 'sample_maec_package.xml' MAEC document
    # Pass in the modified configuration file
    stix_package = maec_to_stix.extract_indicators('sample_maec_package.xml', config_directory="/usr/tmp")
	