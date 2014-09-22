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

from distutils.core import setup

setup(
    name='DPAPI',
    version='0.3',
    packages=['DPAPI', 'DPAPI/Probes', 'DPAPI/Core'],
    scripts=['bin/dpapick'],

    # Metadata
    author='Jean-Michel PICOD',
    author_email='jmichel.p@gmail.com',
    description='DPAPI decryption toolkit',
    license='GPLv3',
    # keywords = '',
    url='http://www.dpapick.com',
    requires=['M2Crypto', 'registry'],
)
