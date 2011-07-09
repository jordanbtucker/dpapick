#!/usr/bin/env python

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

import array, struct
from DPAPI.probe import DPAPIProbe
from DPAPI.Core import blob

class ChromePassword(DPAPIProbe):

    def parse(self, data):
        self.dpapiblob = blob.DPAPIBlob(data.remain())

    def __getattr__(self, name):
        return getattr(self.dpapiblob, name)

    def __repr__(self):
        s = ["Google Chrome Password"]
        if self.dpapiblob != None and self.dpapiblob.decrypted:
            s.append("        password = %s" % self.cleartext)
        s.append("    %r" % self.dpapiblob)
        return "\n".join(s)


# vim:ts=4:expandtab:sw=4
