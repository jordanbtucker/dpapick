#! /usr/bin/env python

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
##  Author: Jean-Michel Picod <jean-michel.picod@cassidian.com>            ##
##                                                                         ##
## This program is distributed under dual cumulative licences:             ##
##    * GPLv3 for non-commercial use of this program (see LICENCE.GPLv3)   ##
##    * EADS licence for commercial use (see LICENCE.EADS)                 ##
##                                                                         ##
## If you want to make a commercial tool using this program, contact the   ##
## author for information and a quotation                                  ##
##                                                                         ##
#############################################################################

from distutils.core import setup

setup(
    name = 'DPAPI',
    version = '0.2',
    packages=['DPAPI', 'DPAPI/Probes', 'DPAPI/Core'],
    scripts = ['bin/dpapidec', 'bin/chrome', 'bin/getcredentialsha1',
               'googletalk'],

    # Metadata
    author = 'Jean-Michel PICOD',
    author_email = 'jean-michel.picod@cassidian.com',
    description = 'DPAPI decryption toolkit',
    license = 'GPLv3 + EADS licence',
    # keywords = '',
    url = 'http://www.dpapick.com',
)
