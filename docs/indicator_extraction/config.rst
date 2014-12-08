Indicator Extraction Configuration
==================================
This page describes the configuration structures employed by **maec-to-stix** for  
indicator extraction and how they may be modified by users in order to customize 
the behavior of the utility.

Overview
--------
Extracting indicators from malware is a process that requires fine tuning
based on a number of internal or external factors. As such, **maec-to-stix**
supports the customization of its behavior in terms of extracting indicators
from MAEC data. This customization can be performed at multiple levels, both
high-level and granular. 

In terms of high-level customization options, **maec-to-stix**
offers the ability to specify:

- Whether to extract indicators for some predefined system activity OR based on a user-specified granular configuration.
- For extracting indicators based on predefined system activity, the particular type of activity to extract indicators for. 

  - E.g., file system, Windows registry, network, etc.
  
- Whether to normalize the indicator output to make it relatively system independent.

With regards to granular customization options, **maec-to-stix**
offers the ability to specify:

- The particular MAEC action types to attempt to extract indicators from.

  - E.g., create file, create registry key, etc.
  
- The particular CybOX object types to attempt to extract indicators from, as well as the specific properties of each object type that are allowable for usage in an indicator.

Configuration Structures
------------------------
The **maec-to-stix** configuration structures are stored in JSON files and have
two distinct levels of granularity. Details of how to edit and use the high-level
and granular configuration files, as well as information about the structures of 
the files themselves can be found at:

* :doc:`config_files`
 
  * :doc:`high_level_config` 
  * :doc:`granular_config`
  
    * :doc:`granular_config_defaults`



