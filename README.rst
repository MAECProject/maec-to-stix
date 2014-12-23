maec-to-stix
===========

A Python library for extracting STIX Indicators from MAEC data, and also wrapping MAEC data in STIX.

:Source: https://github.com/MAECProject/maec-to-stix
:Documentation: http://maec-to-stix.readthedocs.org
:Information: http://maecproject.github.io

Overview
--------

The maec-to-stix package provides APIs and scripts for wrapping MAEC Packages
in STIX, and also extracting STIX Indicators from dynamic analysis data captured
in MAEC. It is compatible with the latest versions of MAEC and STIX,
``4.1`` and ``1.1``, respectively.

Installation
------------

Use pip to install or upgrade stix-ramrod:

::

    $ pip install maec-to-stix [--pre] [--upgrade]

For more information, see the `Installation instructions
<http://maec-to-stix.readthedocs.org/en/latest/installation.html>`_.

Dependencies
------------

The maec-to-stix library depends on the presence of certain packages/libraries
to function. Please refer to their installation documentation for installation
instructions.

-  `python-maec >=4.1.0.9 and <= 4.2.0.0 <https://github.com/MAECProject/python-maec>`_
-  `python-stix >=1.1.1.3 and <= 1.2.0.0. <https://github.com/STIXProject/python-stix>`_
-  `python-cybox >=2.1.0.9 and <= 2.2.0.0. <https://github.com/STIXProject/python-stix>`_

Getting Started
---------------

Read the `Getting Started guide 
<http://maec-to-stix.readthedocs.org/en/latest/getting_started.html>`_.


Layout
------

The stix-ramrod repository has the following layout:

* ``docs/`` - Used to build the `documentation
  <http://maec-to-stix.readthedocs.org>`_.
* ``maec_to_stix/`` - The main stix-ramrod source.
* ``examples/`` - Examples of maec-to-stix usage.


Versioning
----------

Releases of maec-to-stix are given ``major.minor.patch`` version numbers and
follow `semantic versioning <http://semver.org/>`_ guidelines.


Feedback
--------

You are encouraged to provide feedback by commenting on open issues or signing
up for the `MAEC discussion list
<http://maec.mitre.org/community/registration.html>`_ and posting your
questions.


Terms
-----

BY USING MAEC-TO-STIX YOU SIGNIFY YOUR ACCEPTANCE OF THE TERMS AND CONDITIONS
OF USE. IF YOU DO NOT AGREE TO THESE TERMS, DO NOT USE MAEC-TO-STIX.

For more information, please refer to the LICENSE.txt file