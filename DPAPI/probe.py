#!/usr/bin/env python

#############################################################################
##                                                                         ##
## This file is part of DPAPIck                                            ##
## Windows DPAPI decryption & forensic toolkit                             ##
##                                                                         ##
## Copyright (C) Jean-Michel Picod <jmichel.p@gmail.com>                   ##
## Copyright (C) Elie Bursztein <elie@elie.im>                             ##
##                                                                         ##
## This program is free software; you can redistribute it and/or modify it ##
## under the terms of the GNU General Public License version 2 as          ##
## published by the Free Software Foundation.                              ##
##                                                                         ##
## This program is distributed in the hope that it will be useful, but     ##
## WITHOUT ANY WARRANTY; without even the implied warranty of              ##
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       ##
## General Public License for more details.                                ##
##                                                                         ##
#############################################################################

from DPAPI.Core.eater import DataStruct

class DPAPIProbe(DataStruct):

    def __init__(self, raw=None):
        self.dpapiblob = None
        self.cleartext = None
        self.entropy = None
        DataStruct.__init__(self, raw)

    def parse(self, data):
        pass

    def preprocess(self, **k):
        pass

    def postprocess(self, **k):
        pass


# vim:ts=4:expandtab:sw=4

