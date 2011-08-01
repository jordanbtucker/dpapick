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
## This program is distributed under GPLv3 licence (see LICENCE.txt)       ##
##                                                                         ##
#############################################################################

import array, struct
from DPAPI.probe import DPAPIProbe
from DPAPI.Core import blob

class GTalkAccount(DPAPIProbe):

    def parse(self, data):
        self.login = None
        self.raw = data.remain()

    def preprocess(self, **k):
        self.login = k.get("login", None)

        entrop = [ 0x69f31ea3, 0x1fd96207, 0x7d35e91e, 0x487dd24f ]
        seed = 0xba0da71d
        maxint = 0xffffffff

        ## Compute entropy
        arr = array.array('B')
        arr.fromstring(k["username"] + k["computername"])
        for i,v in enumerate(arr):
            entrop[i & 3] ^= (seed * v) & maxint
            seed = (seed * 0xbc8f) & maxint

        self.entropy = "".join(map(lambda y: struct.pack("<L",y&maxint), entrop))

        ## Decode & extract blob
        v = entrop[0] | 1
        arr = array.array('B')
        for i in range(4, len(self.raw), 2):
            a = (((ord(self.raw[i]) - 0x21) << 4) & 0xf0) | ((ord(self.raw[i + 1]) - 0x21) & 0x0f)
            arr.append((a - (v & 0xff)) % 256)
            v = (v * 0x0ff5) & maxint
        self.dpapiblob = blob.DPAPIBlob(arr.tostring())

    def __getattr__(self, name):
        return getattr(self.dpapiblob, name)

    def __repr__(self):
        s = ["Google Talk account"]
        if self.login != None:
            s.append("        login    = %s" % self.login)
        if self.dpapiblob != None and self.dpapiblob.decrypted:
            s.append("        password = %s" % self.cleartext)
        if self.entropy != None:
            s.append("        entropy  = %s" % self.entropy.encode("hex"))
        s.append("    %r" % self.dpapiblob)
        return "\n".join(s)


# vim:ts=4:expandtab:sw=4
