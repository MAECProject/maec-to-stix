Main Configuration File
===========================
This page explains the structure and properties of the main configuration
file (``extractor_config.json``) used in configuring the behavior of the 
indicator extraction capability of **maec-to-stix**.

Structure
---------
The structure of the high-level indicator extraction configuration is as a simple JSON blob:

::

    {
      "use_granular_options":false,
      "normalize_objects":true,
      "abstracted_options": {"file_system_activity":true,
                             "registry_activity":true,
                             "mutex_activity":true,
                             "process_activity":false,
                             "network_activity":true,
                             "service_activity":false,
                             "driver_activity":false},
      "contraindicators": ["delete", "kill"],
      "modifiers": ["move", "copy", "rename"]
    }

.. _main_parameters:

Parameters
----------

===================== ============ ===============================
       Name               Type        Default
===================== ============ ===============================
use_granular_options    Boolean       false
normalize_objects       Boolean       true
driver_activity         Boolean       false
file_system_activity    Boolean       true
registry_activity       Boolean       true
mutex_activity          Boolean       true
process_activity        Boolean       false
network_activity        Boolean       true
service_activity        Boolean       false
contraindicators        List       ["delete", "kill"]
modifiers               List       ["move", "copy", "rename"]
===================== ============ ===============================

Description
~~~~~~~~~~~

- ``use_granular_options``: whether to use the granular configuration file (**granular_config.json**) to drive the indicator extraction behavior, OR to use the abstracted system-level activity configuration files. Thus, a value of **true** indicates that the granular configuration will be used and the abstracted options will not; conversely, a value of **false** indicates that the abstractions will be used and the granular configuration file will not.

- ``normalize_objects``: whether or not the CybOX Objects used in the STIX Indicators should be normalized. For more information on what this entails, please see the Object Normalization section below.

- ``abstracted_options``: the particular set of system-level activities to attempt to extract indicators for, and thus is only applicable if ``use_granular_options`` is set to **false**. The following keys are allowed in the dictionary that specifies the set of system-level activities:

  - ``file_system_activity``: whether to attempt to extract indicators for file-system activity, such as file copying.
  - ``registry_activity``: whether to attempt to extract indicators for Windows registry activity, such as registry key creation.
  - ``mutex_activity``: whether to attempt to extract indicators for mutex activity, such as mutex creation.
  - ``process_activity``: whether to attempt to extract indicators for process activity, such as process creation.
  - ``network_activity``: whether to attempt to extract indicators for network activity, such as connecting to an IP address.
  - ``service_activity``: whether to attempt to extract indicators for service activity, such as service creation.
  - ``driver_activity``: whether to attempt to extract indicators for driver activity, such as driver creation.
  
- ``contraindicators``: a list of terms to look for in MAEC Action names that indicate that an Object may no longer be present after the execution of the malware. Used in candidate Object filtering; for more information please refer to :ref:`contra-indicator`.
- ``modifiers``: a list of terms to look for in MAEC Action names that indicate that the state of the Object may have been changed in some way that would render it undetectable. Primarily applicable to files and used in candidate Object filtering; for more information please refer to :ref:`contra-indicator`.

Object Normalization
--------------------
The underlying differences in the implementation, infrastructure, and environment of 
dynamic anti-malware analysis tools (i.e. sandboxes) means that they all report
things slightly (or vastly, depending on the case) differently, even for the same
malware sample. To help with this, when ``normalize_objects`` is set to **true**,
**maec-to-stix** uses the Normalize_ module from python-cybox to normalize 
certain CybOX Objects and make them independent of the environment in which they were 
recorded. In particular, this module supports normalizing the following objects and 
their corresponding fields:

- File Objects

  - File_Path field. Normalized for common Windows paths/environment variables.

- Windows Registry Key Objects

  - Registry Value/Data field. Normalized for common Windows paths/environment variables.
  - Hive field. Normalized for full representation from abbreviated form. E.g., HKLM -> HKEY_LOCAL_MACHINE.
  
- Process Objects

  - Image_Info/Path field. Normalized for common Windows paths/environment variables.

Example
~~~~~~~

The following example demonstrates the changes made by the the Normalize_ module to an applicable
CybOX Object.

**Before Normalization**

.. code-block:: xml

	<cybox:Object>
		<cybox:Properties xsi:type="FileObj:FileObjectType">
			<FileObj:File_Path condition="Equals">C:\Windows\System32\sdra64.exe</FileObj:File_Path>
		</cybox:Properties>
	</cybox:Object>
	

**After Normalization**

.. code-block:: xml

	<cybox:Object>
		<cybox:Properties xsi:type="FileObj:FileObjectType">
			<FileObj:File_Path condition="Equals">CSIDL_SYSTEM\sdra64.exe</FileObj:File_Path>
		</cybox:Properties>
	</cybox:Object>

.. _Normalize: https://github.com/CybOXProject/python-cybox/blob/master/cybox/utils/normalize.py