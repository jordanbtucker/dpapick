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

import struct
import string
import hashlib
from M2Crypto import *
import crypto
from eater import Eater, DataStruct


class RPC_SID(DataStruct):
    def parse(self, data):
        self.version = data.eat("B")
        n = data.eat("B")
        self.idAuth = struct.unpack(">Q","\0\0"+data.eat("6s"))[0]
        self.subAuth = data.eat("%dL" % n)

    def __str__(self):
        s = ["S-%d-%d" % (self.version, self.idAuth)]
        s += ["%d" % x for x in self.subAuth]
        return "-".join(s)

    def __repr__(self):
        return """RPC_SID(%s):
        revision             = %d
        identifier-authority = %r
        subAuthorities       = %r""" % (self, self.version, self.idAuth, self.subAuth)

class CredSystem(DataStruct):
    def __init__(self, raw=None):
        self.machine = None
        self.user = None
        self.revision = None
        DataStruct.__init__(self, raw)

    def parse(self, data):
        self.revision = data.eat("L")
        self.machine = data.eat("20s")
        self.user = data.eat("20s")

    def __repr__(self):
        s = [ "DPAPI_SYSTEM:" ]
        s.append("\tUser Credential   : %s" % self.user.encode('hex'))
        s.append("\tMachine Credential: %s" % self.machine.encode('hex'))
        return "\n".join(s)

class CredhistEntry(DataStruct):
    """Represents an entry in the Credhist file"""
    def __init__(self, raw=None):
        self.pwdhash = None
        self.hmac = None
        DataStruct.__init__(self, raw)

    def parse(self, data):
        self.revision = data.eat("L")
        self.hashAlgo = crypto.CryptoAlgo(data.eat("L"))
        self.rounds = data.eat("L")
        data.eat("L")
        self.cipherAlgo = crypto.CryptoAlgo(data.eat("L"))
        self.dataLen = data.eat("L")
        self.hmacLen = data.eat("L")
        self.iv = data.eat("16s")

        self.userSID = RPC_SID()
        self.userSID.parse(data)

        n = self.dataLen + self.hmacLen
        n += -n % self.cipherAlgo.blockSize
        self.encrypted = data.eat_string(n)
        
        self.revision2 = data.eat("L")
        self.guid = "%0x-%0x-%0x-%0x%0x-%0x%0x%0x%0x%0x%0x" % data.eat("L2H8B")

    def decryptWithHash(self, pwdhash):
        utf_userSID = (str(self.userSID)+"\0").encode("UTF-16LE")
        cleartxt = crypto.dataDecrypt(self.cipherAlgo, self.hashAlgo, self.encrypted, 
                                      pwdhash, self.iv, utf_userSID, self.rounds)
        self.pwdhash = cleartxt[:self.dataLen]
        self.hmac = cleartxt[self.dataLen:self.dataLen+self.hmacLen]

        ##TODO: Compute & Verify HMAC

    def decryptWithPassword(self, password):
        return self.decryptWithHash(hashlib.sha1(password.encode("UTF-16LE")).digest())

    def __repr__(self):
        s = ["""CredHist entry
        revision = %(revision)x
        hash     = %(hashAlgo)r
        rounds   = %(rounds)i
        cipher   = %(cipherAlgo)r
        dataLen  = %(dataLen)i
        hmacLen  = %(hmacLen)i
        userSID  = %(userSID)s""" % self.__dict__]
        s.append("\tguid     = %s" % self.guid)
        s.append("\tiv       = %s" % self.iv.encode("hex"))
        if self.pwdhash is not None:
            s.append("\tpwdhash  = %s" % self.pwdhash.encode("hex"))
        if self.hmac is not None:
            s.append("\thmac     = %s" % self.hmac.encode("hex"))
        return "\n".join(s)


class CredHistFile(DataStruct):
    def __init__(self, raw=None):
        self.entries_list = []
        self.entries = {}
        
        DataStruct.__init__(self, raw)

    def parse(self, data):
        while True:
            l = data.pop("L")
            if l == 0:
                break
            self.addEntry(data.pop_string(l-4))
        
        self.footmagic = data.eat("L")
        self.curr_guid = "%0x-%0x-%0x-%0x%0x-%0x%0x%0x%0x%0x%0x" % data.eat("L2H8B")

    def addEntry(self, blob):
        x = CredhistEntry(blob)
        self.entries[x.guid] = x
        self.entries_list.append(x)
 
    def decryptWithHash(self, h):
        curhash = h
        for entry in self.entries_list:
            entry.decryptWithHash(curhash)
            curhash = entry.pwdhash

    def decryptWithPassword(self, pwd):
        return self.decryptWithHash(hashlib.sha1(pwd.encode("UTF-16LE")).digest())

    def __repr__(self):
        s = ["CredHistPool:  %s" % self.curr_guid]
        for e in self.entries.itervalues():
            s.append("---")
            s.append(repr(e))
        s.append("====")
        return "\n".join(s)
    

# vim:ts=4:expandtab:sw=4
