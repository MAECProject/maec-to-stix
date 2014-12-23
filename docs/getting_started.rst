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

maec_wrap.py
~~~~~~~~~~~~

Bundled with **maec-to-stix** is ``maec_wrap.py``, which is used for wrapping
MAEC Package documents in STIX. It can be found on your ``PATH`` after
installing **maec-to-stix**.

Options
^^^^^^^

Running :code:`maec_wrap.py -h` displays the following:

.. code-block:: bash

    $ maec_wrap.py -h
      usage: maec_wrap.py [-h] [--outfile OUTFILE] infile

      MAEC to STIX Wrapper Script v1.0.0-alpha1

      positional arguments:
        infile                the name of the input MAEC Package XML file to wrap in
                              STIX.

      optional arguments:
        -h, --help            show this help message and exit
        --outfile OUTFILE, -o OUTFILE
                              the name of the output STIX Package XML file. If not
                              specified, defaults to sys.stdout.

Basics
,,,,,,

To wrap a MAEC Package in STIX, just provide the input filename 
and optionally the output filename, respectively. If no output filename is
specified, the script will print the output STIX Package to ``sys.stdout``.

.. code-block:: bash

    $ maec_wrap.py maec_doc.xml --outfile stix_doc.xml

maec_extract_indicators.py
~~~~~~~~~~~~~~~~~~~~~~~~~~

Also bundled with **maec-to-stix** is ``maec_extract_indicators.py``, which is
used for extracting indicators from MAEC documents and outputting them in a STIX
Package. It can likewise be found on your ``PATH`` after installing **maec-to-stix**.

Options
^^^^^^^

Running :code:`maec_extract_indicators.py -h` displays the following:

.. code-block:: bash

    $ maec_extract_indicators.py -h
      usage: maec_extract_indicators.py [-h] [--outfile OUTFILE]
                                        [--config_directory CONFIG_DIRECTORY]
                                        [--print_options]
                                        infile

      MAEC to STIX Indicator Extraction Script v1.0.0-alpha1

      positional arguments:
        infile                the name of the input MAEC Package XML file to extract
                              indicators from.

      optional arguments:
        -h, --help            show this help message and exit
        --outfile OUTFILE, -o OUTFILE
                              the name of the output STIX Package XML file. If not
                              specified, defaults to sys.stdout.
        --config_directory CONFIG_DIRECTORY, -c CONFIG_DIRECTORY
                              the path to the directory housing the Indicator
                              extraction JSON configuration files.
        --print_options, -p   print out the current set of indicator extraction
                              options, including the supported Actions and Objects.

Basics
,,,,,,

To extract STIX Indicators from a MAEC ``MAEC Package``, just provide the 
input filename and optionally the output filename, respectively. If no output
filename is specified, the script will print the output STIX Package to
``sys.stdout``. Note that the behavior of the Indicator extraction is driven
by a set of JSON configuration files, covered in :doc:`indicator_extraction/config`.
For more information on the indicator extraction process itself, please refer to
:doc:`indicator_extraction/process`.

.. code-block:: bash

    $ maec_extract_indicators.py maec_doc.xml --outfile stix_doc.xml

.. _copy-config:

copy_maec_to_stix_config.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~
The other script bundled with **maec-to-stix** is ``copy_maec_to_stix_config.py``,
which is simply intended to copy over the installed JSON indicator extraction
configuration files to a user specified directory. For more information on the
indicator extraction configuration files, please refer to 
:doc:`indicator_extraction/config`.

Options
^^^^^^^

Running :code:`copy_maec_to_stix_config.py -h` displays the following:

.. code-block:: bash

    $ maec_to_stix.py -h
      usage: copy_maec_to_stix_config.py [-h] outpath

      MAEC to STIX configuration copying script

      positional arguments:
        outpath     the output directory into which the MAEC to STIX Indicator
                    extraction configuration files will be copied. If the directory
                    does not already exist, it will be created by the script.

      optional arguments:
        -h, --help  show this help message and exit

Basics
^^^^^^
The only argument to the script is ``outpath``, which should point to a
directory into which the JSON indicator extraction configuration files will be
copied. Note that if this directory does not exist, it will be created by the
script.

.. code-block:: bash

    $ copy_maec_to_stix_config.py "temp\json_config"
