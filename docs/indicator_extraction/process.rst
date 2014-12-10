Indicator Extraction Process
============================
This page details the Indicator extraction process used in **maec-to-stix**.

Configuration Parsing
---------------------
The first step involves parsing the JSON configuration files in order to build
up the list of supported MAEC Actions and CybOX Objects (along with their
properties). For more information on the configuration files, including how they
can be edited and used, please refer to :doc:`config_files`.

MAEC Package Parsing
--------------------
The next step is the parsing of the MAEC Package, including its child Malware
Subjects and their embedded Findings Bundles (which may contain MAEC Actions).
Accordingly, a STIX TTP is created for each Malware Subject, and then referenced
in the ``Indicated_TTP`` field of each STIX Indicator that gets extracted from
the Malware Subject.

Indicator Object Selection & Filtering
--------------------------------------
The process of selecting and filtering the CybOX Objects suitable for use in
Indicators itself contains several sub-steps, detailed below. This is done on a
per-Bundle basis.

Candidate Object Selection
~~~~~~~~~~~~~~~~~~~~~~~~~~~
The initial sub-step with regards to constructing Indicators is to create the
candidate list of CybOX Objects that may potentially be used as Indicators. 
This is accomplished by creating an `ObjectHistory`_ instance for the Bundle, 
which contains a list of the Objects found in the Bundle along with the Actions 
that operated on them. This latter aspect is important, as the candidate Objects 
are selected on the basis of having *at least one* supported MAEC Action 
(as parsed in from the configuration files) that operates on them. 

For example, suppose the following Actions and Objects are defined as supported:

* **Supported Actions**: create file
* **Supported Objects**: File Object


Thus, only the second Object History entry would be considered a candidate
Object, as it contains a supported Action.

============= ============================ ===================
Object           Actions                     Candidate Object
============= ============================ ===================
File Object    modify file, move file         No
File Object    create file, write to file     **Yes**
============= ============================ ===================

.. _ObjectHistory: http://maec.readthedocs.org/en/latest/api/bundle/object_history.html#maec.bundle.object_history.ObjectHistory

Candidate Object Filtering
~~~~~~~~~~~~~~~~~~~~~~~~~~
After creating the list of candidate CybOX Objects, the next step is to further
filter this list based on the requirements dictated by the configuration files
as well as some further sanity checking. 

.. _contra-indicator:

Contra-indicator Testing
^^^^^^^^^^^^^^^^^^^^^^^^
The first step in the candidate CybOX Object filtering process is the testing
of the Object History entries for contra-indicators. By this, we mean testing for
the existence of specific Actions performed on the Object that modify its state 
and thus may render it unusable for detection. For example, deleting a file that
was created would mean that it may not be detectable and thus unsuitable for use 
as an Indicator.

This logic operates by checking for specific terms in the names of the Actions
that operate on the Object, including for direct contra-indicators (such as "delete"), 
and also for modifiers (such as "move") where the Object may be used as an input
to the Action. Both of these sets of terms are captured as lists in the main 
indicator extraction configuration file; for more information please refer to
:ref:`main_parameters`.

For example, suppose the following list of contra-indicators and modifiers is
defined:

* **Contra-indicators**: delete
* **Modifiers**: move

Thus, the first two Object History inputs below would not pass the filter,
as they contain Actions that serve as contra-indicators for the presence
of the Object.

============= ============================ ===================
Object           Actions                     Contra-indicator
============= ============================ ===================
File Object    create file, move file         **Yes**
File Object    create file, delete file       **Yes**
File Object    create file, write to file       No
============= ============================ ===================

Required Property Testing
^^^^^^^^^^^^^^^^^^^^^^^^^
If an Object History entry passes the contra-indicator tests, the next step in the 
filtering process is to test whether it contains the required set of properties, 
as specified in the :doc:`granular_config`. For example, a file Object would not
be very useful without a file path that states where it can be found, or more 
generally an MD5 (or other) hash value. Thus, this logic checks for the existence
of any required (or mutually exclusive required) properties that are defined
for a particular Object type. 

Also checked here is whether the value of an Object property matches against
any of the whitelist entries specified in the configuration parameters for the
property. Such whitelist entries are intended to specify values that are 
*whitelisted* from being searched for and therefore used in indicators. For example,
internal IP addresses would be good candidates for additions to such a whitelist,
as they would not make useful indicators. If an Object property value matches against
a whitelist entry, the property will not be included in the corresponding Indicator. 
If such a property is required (or mutually exclusive required), this means that its
parent Object will be discarded and not used in a STIX Indicator. For more information
on how Object properties may be configured, including the use of the whitelist, please
refer to :ref:`object_parameters`.

Extraneous Property Pruning
^^^^^^^^^^^^^^^^^^^^^^^^^^^
If a CybOX Object passes the required property testing, the final step in the
Object filtering process is to prune from it any extraneous properties, that is
those that aren't specified as required or optional in the :doc:`granular_config`.
With this step complete, the resulting list of CybOX Objects represents the final
Objects that will end up being used in the construction of the STIX Indicators.

Final Object Preparation
~~~~~~~~~~~~~~~~~~~~~~~~
With the list of final (filtered and pruned) CybOX Objects constructed, there's one
more step that must be done before these Objects can be used in STIX Indicators.
Because these Objects came from *instance* data as reported by a dynamic analysis
tool (i.e. sandbox), we need to modify them so that they now represent *patterns*
capable of being used in detection. This is achieved by setting the **condition** 
attribute on each property of the Object; by default, this is set to a value of
**Equals**. 

STIX Indicator Creation
-----------------------
The final step is the creation of the STIX Indicators themselves, one per each
of the final CybOX Objects described above. Besides using the CybOX Object in the
Observable of each Indicator, the following fields are populated:

* Title: states that the Indicator represents a malware artifact extracted from a MAEC document
* Type: set to "Malware Artifacts" from the ``IndicatorTypeVocab``
* Description: includes the set of Actions that operated on the Object, e.g. "create file"
* Indicated_TTP: references the TTP that corresponds to the Malware Subject from which the Indicator was extracted
* Confidence/Value: set to a value of "Low" to denote that the Indicator was tool-generated


