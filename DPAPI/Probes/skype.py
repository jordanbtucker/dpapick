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

from xml.etree.ElementTree import ElementTree
from M2Crypto import EVP, m2
from DPAPI.probe import DPAPIProbe
from DPAPI.Core import blob
import hashlib, struct, array

class SkypeAccount(DPAPIProbe):

    def parse(self, data):
        self.login = None
        self.cleartext = None
        self.dpapiblob = blob.DPAPIBlob(data.remain())
        self.entropy = None

    def preprocess(self, **k):
        self.login = k.get('login')
        tree = ElementTree()
        if k.get('xmlfile') != None:
            tree.parse(k['xmlfile'])
        else:
            tree.fromstring(k['xml'])
        self.cred = tree.find(".//Account/Credentials2")
        if self.cred == None:
            self.cred = tree.find(".//Account/Credentials3")
        if self.cred != None:
            self.cred = self.cred.text.decode('hex')

    def postprocess(self, **k):
        if self.cred == None:
            return
        ## use SHA-1 counter mode to expand the key
        k = hashlib.sha1(struct.pack(">L", 0) +
                self.dpapiblob.cleartext).digest()
        k += hashlib.sha1(struct.pack(">L", 1) +
                self.dpapiblob.cleartext).digest()
        ## use AES-256 CTR mode
        ciph = EVP.Cipher("aes_256_ecb", k[:32], "", m2.encrypt, 0)
        arr = array.array("B")
        arr.fromstring(self.cred)
        for i in range(0, len(self.cred), 16):
            buff = ciph.update("\0"*12 + struct.pack(">L", i>>4))
            for j in range(min(16, len(self.cred) - i)):
                arr[i + j] ^= ord(buff[j])
        self.cleartext = arr.tostring().encode('hex')

    def __getattr__(self, name):
        return getattr(self.dpapiblob, name)

    def jtr_shadow(self):
        if self.login is not None:
            return "%s:$dynamic_1401$%s" % (self.login, self.cleartext[:32])
        return ""

    def __repr__(self):
        s = ["Skype account"]
        if self.login != None:
            s.append("        login = %s" % self.login)
        s.append("        hash  = %s" % self.cleartext[:32])
        return "\n".join(s)


# vim:ts=4:expandtab:sw=4
