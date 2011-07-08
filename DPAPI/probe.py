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

from DPAPI.Core.eater import DataStruct
from DPAPI.Core import masterkey
import hashlib

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

    def try_decrypt_with_hash(self, h, mkeypool, sid, **k):
        self.preprocess(**k)
        for kguid in self.dpapiblob.guids:
            mks = mkeypool.getMasterKeys(kguid)
            for mk in mks:
                mk.decryptWithHash(sid, h)
                if mk.decrypted:
                    self.dpapiblob.decrypt(mk.get_key(),
                            self.entropy,
                            k.get("strong", None))
                    if self.dpapiblob.decrypted:
                        self.postprocess(**k)
                        return True
        return False

    def try_decrypt_with_password(self, password, mkeypool, sid, **k):
        return self.try_decrypt_with_hash(
                hashlib.sha1(password.encode("UTF-16LE")).digest(),
                mkeypool, sid, **k)

# vim:ts=4:expandtab:sw=4

