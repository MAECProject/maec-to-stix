Getting Started
===============

This page gives an introduction to **maec-to-stix** and how to use it.  Please
note that this page is being actively worked on and feedback is welcome! If
you have a suggestion or something doesn't look right, let us know:
(maec@mitre.org).

Note that the GitHub repository is named :code:`maec-to-stix`, but
once installed, the library is imported using the :code:`import maec_to_stix`
statement.

Installation
------------

To install **maec-to-stix** just run :code:`pip install maec-to-stix**`. If you have
any issues, please refer to the instructions found on the
:doc:`/installation` page.

Scripts
-------

These instructions tell you how to wrap MAEC content in STIX or extract STIX
Indicators from MAEC content using the scripts bundled with **maec-to-stix****.


maec_to_stix.py
~~~~~~~~~~~~~

Currently, the only script bundled with **maec-to-stix** is the
``maec_to_stix.py`` script, which can be found on your ``PATH`` after
installing **maec-to-stix**.

Options
^^^^^^^

Running :code:`maec_to_stix.py -h` displays the following:

.. code-block:: bash

    $ maec_to_stix.py -h
	  usage: maec_to_stix.py [-h] [-input INPUT] [-output OUTPUT]
						   [--wrap | --extract | --print_options]

	  MAEC to STIX 1.0.0-alpha1

	  optional arguments:
	    -h, --help            show this help message and exit
	    -infile INPUT, -i INPUT
							  the name of the input MAEC Package XML file.
	    -outfile OUTPUT, -o OUTPUT
							  the name of the output STIX Package XML file.
	    --wrap, -w            wrap the input MAEC Package file in a STIX Package.
	    --extract, -e         attempt to extract indicators from the MAEC Package
							  and output them in a new STIX Package.
	    --print_options, -p   print out the current set of indicator extraction
							  options, including the supported Actions and Objects.

Flags
^^^^^

The ``maec-to-stix.py`` accepts a MAEC ``MAEC Package`` or
document as input. However, what it does with this document is determined
by the particular flag that is provided, either ``--wrap`` or ``--extract``.
We discuss the corresponding behavior of both flags and their usage below.

Wrapping MAEC Content in STIX
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In this section, we'll discuss the usage of the ``--wrap`` flag for
wrapping MAEC content in a STIX ``STIX Package``.

Basics
,,,,,,

To wrap the MAEC Package in STIX, just provide the ``--wrap`` flag, along with the 
``-infile`` and ``-outfile`` arguments which specify the input filename 
and output filename, respectively. 

.. code-block:: bash

    $ maec_to_stix.py --wrap -infile maec_doc.xml -outfile stix_doc.xml

Extracting STIX Indicators from MAEC
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In this section, we'll discuss the usage of the ``--extract`` flag for
extracting STIX Indicators from a MAEC ``MAEC Package``.

Basics
,,,,,,

To extract STIX Indicators from a MAEC ``MAEC Package``, just provide the 
``--extract`` flag, along with the ``-infile`` and ``-outfile`` arguments which
specify the input filename and output filename, respectively. Note that the 
behavior of this extraction is driven by a set of JSON configuration files,
documented in configuration.

.. code-block:: bash

    $ maec_to_stix.py --extract -infile maec_doc.xml -outfile stix_doc.xml
