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

To install **maec-to-stix** just run :code:`pip install maec-to-stix`. If you have
any issues, please refer to the instructions found on the
:doc:`/installation` page.

Scripts
-------

These instructions tell you how to wrap MAEC content in STIX or extract STIX
Indicators from MAEC content using the scripts bundled with **maec-to-stix**.

Also discussed is the copying over of the JSON indicator extraction configuration
files to a user specified directory.

maec_2_stix.py
~~~~~~~~~~~~~~

The main script bundled with **maec-to-stix** is ``maec_2_stix.py``, which can be
found on your ``PATH`` after installing **maec-to-stix**.

Options
^^^^^^^

Running :code:`maec_2_stix.py -h` displays the following:

.. code-block:: bash

    $ maec_to_stix.py -h
      usage: maec_2_stix.py [-h] [-infile INFILE] [-outfile OUTFILE]
                            [-config_file CONFIG_FILE]
                            [--wrap | --extract | --print_options]

      MAEC to STIX 1.0.0-alpha1

      optional arguments:
        -h, --help            show this help message and exit
        --infile INFILE, -i INFILE
                              the name of the input MAEC Package XML file.
        --outfile OUTFILE, -o OUTFILE
                              the name of the output STIX Package XML file.
        --config_directory CONFIG_DIRECTORY, -c CONFIG_DIRECTORY
                              the path to the directory housing the Indicator
                              extraction JSON configuration files.
        --wrap, -w            wrap the input MAEC Package file in a STIX Package.
        --extract, -e         attempt to extract indicators from the MAEC Package
                              and output them in a new STIX Package.
        --print_options, -p   print out the current set of indicator extraction
                              options, including the supported Actions and Objects.

Flags
^^^^^

The ``maec_2_stix.py`` script accepts a MAEC ``MAEC Package`` or
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
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In this section, we'll discuss the usage of the ``--extract`` flag for
extracting STIX Indicators from a MAEC ``MAEC Package``.

Basics
,,,,,,

To extract STIX Indicators from a MAEC ``MAEC Package``, just provide the 
``--extract`` flag, along with the ``-infile`` and ``-outfile`` arguments which
specify the input filename and output filename, respectively. Note that the 
behavior of this extraction is driven by a set of JSON configuration files,
covered in :doc:`indicator_extraction/config`. For more information on the
indicator extraction process itself, please refer to 
:doc:`indicator_extraction/process`.

.. code-block:: bash

    $ maec_to_stix.py --extract -infile maec_doc.xml -outfile stix_doc.xml

.. _copy-config:

copy_config.py
~~~~~~~~~~~~~~
The other script bundled with **maec-to-stix** is ``copy_config.py``,
which is simply intended to copy over the installed JSON indicator extraction
configuration files to a user specified directory. For more information on the
indicator extraction configuration files, please refer to 
:doc:`indicator_extraction/config`.

Options
^^^^^^^

Running :code:`copy_config.py -h` displays the following:

.. code-block:: bash

    $ maec_to_stix.py -h
      usage: copy_config.py [-h] outpath

      MAEC to STIX configuration copying script

      positional arguments:
        outpath     the output directory into which to copy the MAEC to STIX
                    Indicator extraction configuration files. If the directory does
                    not already exist, it will be created by the script.

      optional arguments:
        -h, --help  show this help message and exit

Basics
^^^^^^
The only argument to the script is ``outpath``, which should point to a
directory into which the JSON indicator extraction configuration files will be
copied. Note that if this directory does not exist, it will be created by the
script.

.. code-block:: bash

    $ copy_config.py "temp\json_config"
		