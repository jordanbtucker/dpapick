#!/usr/bin/env python
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
##                                                                         ##
## Dropbox DBX password                                                    ##
##                                                                         ##
## The following code ia based on the awesome research made by             ##
## Florian Ledoux and Nicolas Ruff                                         ##
## "A critical analysis of Dropbox software security"                      ##
## Open Source code here: https://github.com/newsoft                       ##
##                                                                         ##
##  Author: Francesco Picasso <francesco.picasso@gmail.com>                ##
##                                                                         ##
#############################################################################

from DPAPI import probe
from DPAPI.Core import blob

import hmac
import M2Crypto

class Dropbox(probe.DPAPIProbe):
    """Dropbox DBX password decryptor, Version 0"""
  
    # TODO: make a better versioning.
    V0_HMAC_KEY = '\xd1\x14\xa5R\x12e_t\xbdw.7\xe6J\xee\x9b'
    V0_APP_KEY = '\rc\x8c\t.\x8b\x82\xfcE(\x83\xf9_5[\x8e'
    V0_APP_IV = '\xd8\x9bC\x1f\xb6\x1d\xde\x1a\xfd\xa4\xb7\xf9\xf4\xb8\r\x05'
    V0_APP_ITER = 1066
    V0_USER_KEYLEN = 16
    V0_DB_KEYLEN = 16

    def __init__(self, version, raw, crc, ks):
        super(probe.DPAPIProbe, self).__init__(raw)
        self.version = version
        self.crc = crc
        self.ks = ks
        self.crc_ok = False
        self.entropy = self.V0_HMAC_KEY
        self.user_key = None
        self.dbx_key = None
 
    def preprocess(self, **k):
        hm = hmac.new(self.V0_HMAC_KEY)
        if hm.digest_size == len(self.crc):
            hm.update(self.ks[:-hm.digest_size])
            if hm.digest() == self.crc:
                self.crc_ok = True

    def parse(self, data):
        self.dpapiblob = blob.DPAPIBlob(data.remain())
        
    def postprocess(self, **k):
        if self.dpapiblob.decrypted:
            self.user_key = self.dpapiblob.cleartext
            self.dbx_key = M2Crypto.EVP.pbkdf2(
                    self.user_key, self.V0_APP_KEY, self.V0_APP_ITER, self.V0_DB_KEYLEN)

    def __getattr__(self, name):
        return getattr(self.dpapiblob, name)

    def __repr__(self):
        s = ["\nDropbox DBX password"]
        if self.dpapiblob is not None and self.dpapiblob.decrypted:
            s.append("%s\n" % self.user_key.encode('hex'))
            if self.version != 0:
                s.append("*WARNING* version is not 0 but %s" % self.version)
                s.append("          The DBX password could be wrong!")
            if self.crc_ok is False:
                s.append("*WARNING* Drobox DPAPI blob CRC check failed!")
                s.append("          The DBX password could be wrong!")
        #s.append("    %r" % self.dpapiblob)
        return "\n".join(s)

# vim:ts=4:expandtab:sw=4
