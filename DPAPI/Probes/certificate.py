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
##  Author: Jean-Michel Picod <jean-michel.picod@cassidian.com>            ##
##                                                                         ##
## This program is distributed under GPLv3 licence (see LICENCE.txt)       ##
##                                                                         ##
#############################################################################

from DPAPI.probe import DPAPIProbe
from DPAPI.Core import blob

class PrivateKeyBlob(DPAPIProbe):
    class RSAHeader(DPAPIProbe):
        def parse(self, data):
            self.magic = data.eat("4s") # RSA1
            self.len1 = data.eat("L")
            self.unk1 = data.eat("L") # 0x400
            self.unk2 = data.eat("L") # 0x7F
            self.unk3 = data.eat("L") # 0X00010001
            self.data = data.eat("%is" % self.len1) ## !! ends with 8 NULL-bytes

        def __repr__(self):
            s = [ "RSA header" ]
            s.append("\tmagic    = %s" % self.magic)
            s.append("\tunknown1 = %x" % self.unk1)
            s.append("\tunknown2 = %x" % self.unk2)
            s.append("\tunknown3 = %x" % self.unk3)
            s.append("\tdata     = %s" % self.data.encode('hex'))
            return "\n".join(s)

    class RSAPrivKey(DPAPIProbe):
        def parse(self, data):
            self.dpapiblob = blob.DPAPIBlob(data.remain())

        def __repr__(self):
            s = [ "RSA Private Key" ]
            if self.entropy:
                s.append("entropy = %s" % self.entropy.encode('hex'))
            if hasattr(self, "strong"):
                s.append("strong = %s" % self.strong.encode('hex'))
            s.append(repr(self.dpapiblob))
            return "\n".join(s)

    class RSAFlags(DPAPIProbe):
        def parse(self, data):
            self.dpapiblob = blob.DPAPIBlob(data.remain())

        def preprocess(self, **k):
            self.entropy = "Hj1diQ6kpUx7VC4m\0"
            if hasattr(k, "strong"):
                self.strong = k["strong"]

        def __repr__(self):
            s = [ "Export Flags" ]
            s.append("entropy = %s" % self.entropy)
            if hasattr(self, "strong"):
                s.append("strong = %s" % self.strong.encode("hex"))
            s.append("%r" % self.dpapiblob)
            return "\n".join(s)

    def parse(self, data):
        self.version = data.eat("L")
        data.eat("L") # NULL
        self.descrLen = data.eat("L")
        data.eat("2L") # NULL NULL
        headerlen = data.eat("L")
        privkeylen = data.eat("L")
        self.crcLen = data.eat("L")
        data.eat("L") ## NULL
        flagslen = data.eat("L")

        self.description = data.eat("%is" % self.descrLen)

        self.header = None
        if headerlen > 0:
            data.eat("5L") # 20 NULL-bytes ...
            self.header = self.RSAHeader()
            self.header.parse(data.eat_sub(headerlen))

        self.privateKey = None
        if privkeylen > 0:
            self.privateKey = self.RSAPrivKey()
            self.privateKey.parse(data.eat_sub(privkeylen))

        self.flags = None
        if flagslen > 0:
            self.flags = self.RSAFlags()
            self.flags.parse(data.eat_sub(flagslen))

    def try_decrypt_with_hash(self, h, mkp, sid, **k):
        if self.flags != None:
            if self.flags.try_decrypt_with_hash(h, mkp, sid, **k):
                self.privateKey.entropy = self.flags.cleartext
                return self.privateKey.try_decrypt_with_hash(h, mkp, sid, **k)
        else:
            return True
        return False

    def __repr__(self):
        s = [ "Microsoft Certificate" ]
        s.append("\tdescr: %s" % self.description)
        if self.header != None:
            s.append("+  %r" % self.header)
        if self.privateKey != None:
            s.append("+  %r" % self.privateKey)
        if self.flags != None:
            s.append("+  %r" % self.flags)
        return "\n".join(s)


# vim:ts=4:expandtab:sw=4
