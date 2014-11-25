# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

from os.path import abspath, dirname, join
from setuptools import setup, find_packages

INIT_FILE = join(dirname(abspath(__file__)), 'maec_to_stix', '__init__.py')

def get_version():
    with open(INIT_FILE) as f:
        for line in f.readlines():
            if line.startswith("__version__"):
                version = line.split()[-1].strip('"')
                return version
        raise AttributeError("Package does not have a __version__")

with open('README.rst') as f:
    readme = f.read()

setup(
    name="maec_to_stix",
    version=get_version(),
    author="MAEC Project",
    author_email="maec@mitre.org",
    description="A utility/API for wrapping MAEC documents in STIX and also extracting STIX Indicators from MAEC documents.",
    long_description=readme,
    url="http://maec.mitre.org",
    packages=find_packages(),
    include_package_data=True,
    package_data={'maec_to_stix': ['config/*.json']},
    install_requires=['maec>=4.1.0.8,<4.1.1.0', 'cybox>=2.1.0.8,<2.1.1.0', 'stix>=1.1.1.2,<1.2.0.0'],
    classifiers=[
        "Programming Language :: Python",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
    ]
)
