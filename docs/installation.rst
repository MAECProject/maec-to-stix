.. _installation:

Installation
============

The installation of maec-to-stix can be accomplished through a few different
workflows.

Recommended Installation
------------------------

Use PyPI_ and pip_:

.. code-block:: bash

    $ pip install maec-to-stix [--pre] [--upgrade]

.. note::
    **maec-to-stix** is currently in **alpha** status. To install an alpha or
    beta release via ``pip``, you must specify the version number or use
    ``--pre``.

    .. code-block:: bash

        $ pip install maec-to-stix --pre



You might also want to consider using a virtualenv_.
Please refer to the `pip installation instructions`_ for details regarding the
installation of pip.

.. _pypi: https://pypi.python.org/pypi/maec-to-stix/
.. _pip: http://pip.readthedocs.org/
.. _pip installation instructions: http://www.pip-installer.org/en/latest/installing.html
.. _virtualenv: http://virtualenv.readthedocs.org/


Dependencies
------------

The maec-to-stix package relies on some non-standard Python libraries for the
processing of XML content. Revisions of maec-to-stix may depend on particular
versions of dependencies to function correctly. These versions are detailed
within the distutils setup.py installation script.

The following libraries are required to use maec-to-stix:

* python-maec_ - A python library for parsing and creating MAEC content.
* python-stix_ - A python library for parsing and creating STIX content.

Each of these can be installed with ``pip`` or by manually downloading packages
from PyPI. 

.. _python-maec: https://github.com/MAECProject/python-maec
.. _python-stix: https://github.com/STIXProject/python-stix


Manual Installation
-------------------

If you are unable to use pip, you can also install maec-to-stix with setuptools_.
If you don't already have setuptools installed, please install it before
continuing.

1. Download and install the dependencies_ above. Although setuptools will
   generally install dependencies automatically, installing the dependencies
   manually beforehand helps distinguish errors in dependency installation from
   errors in maec-to-stix installation. Make sure you check to ensure the
   versions you install are compatible with the version of maec-to-stix you plan
   to install.

2. Download the desired version of maec-to-stix from PyPI_ or the GitHub releases_
   page. The steps below assume you are using the |release| release.

3. Extract the downloaded file. This will leave you with a directory named
   maec-to-stix-|release|.

.. parsed-literal::
    $ tar -zxf maec-to-stix-|release|.tar.gz
    $ ls
    maec-to-stix-|release| maec-to-stix-|release|.tar.gz

OR

.. parsed-literal::
    $ unzip maec-to-stix-|release|.zip
    $ ls
    maec-to-stix-|release| maec-to-stix-|release|.zip

4. Run the installation script.

.. parsed-literal::
    $ cd maec-to-stix-|release|
    $ python setup.py install

5. Test the installation.

.. parsed-literal::
    $ python
    Python 2.7.8 (default, Mar 22 2015, 22:59:56)
    [GCC 4.8.2] on linux2
    Type "help", "copyright", "credits" or "license" for more information.
    >>> import maec_to_stix
    >>> print maec_to_stix.__version__
    1.0.0-alpha1

If you don't see an ``ImportError``, the installation was successful.

.. _setuptools: https://pypi.python.org/pypi/setuptools/
.. _releases: https://github.com/MAECProject/maec-to-stix/releases


Further Information
-------------------

If you're new to installing Python packages, you can learn more at the `Python
Packaging User Guide`_, specifically the `Installing Python Packages`_ section.

.. _Python Packaging User Guide: http://python-packaging-user-guide.readthedocs.org/
.. _Installing Python Packages: http://python-packaging-user-guide.readthedocs.org/en/latest/tutorial.html#installing-python-packages