#! /usr/bin/env python
# -*- coding: utf-8 -*-

#############################################################################
##                                                                         ##
## This file is part of DPAPIck                                            ##
## Windows DPAPI decryption & forensic toolkit                             ##
##                                                                         ##
##                                                                         ##
## Copyright (C) 2010, 2011 Cassidian SAS. All rights reserved.            ##
## This document is the property of Cassidian SAS, it may not be copied or ##
## circulated without prior licence                                        ##
##                                                                         ##
##  Author: Jean-Michel Picod <jmichel.p@gmail.com>                        ##
##                                                                         ##
## This program is distributed under GPLv3 licence (see LICENCE.txt)       ##
##                                                                         ##
#############################################################################

from setuptools import setup


setup(
    name='DPAPI',
    version='0.3',
    packages=['DPAPI', 'DPAPI/Probes', 'DPAPI/Core'],
    scripts=['bin/dpapidec'],

    # Metadata
    author='Jean-Michel PICOD',
    author_email='jmichel.p@gmail.com',
    description='DPAPI decryption toolkit',
    license='GPLv3',
    # keywords = '',
    url='http://www.dpapick.com',
    install_requires=['M2Crypto', 'python-registry>=1.0.4'],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Recovery Tools"
    ]
)
