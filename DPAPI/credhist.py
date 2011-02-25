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

import struct
import string
from crypto import *
import hashlib
from M2Crypto import *
from eater import Eater, DataStruct


class RPC_SID(DataStruct):
    def parse(self, data):
        self.version = data.eat("B")
        n = data.eat("B")
        self.idAuth = struct.unpack("<Q",data.eat("6s")+"\0\0")[0]
        self.subAuth = data.eat("%dL" % n)

    def __str__(self):
        s = ["S-%d-%d" % (self.version, self.idAuth)]
        s += ["%d" % x for x in self.subAuth]
        return "-".join(s)

    def __repr__(self):
        return """RPC_SID(%s):
        revision: %d
        identifier-authority: %r
        subAuthorities: %r""" % (self, self.version, self.idAuth, self.subAuth)

class CredhistEntry(DataStruct):
    """Represents an entry in the Credhist file"""
    def __init__(self, raw=None):
        self.password = None
        self.hmac = None
        DataStruct.__init__(self, raw)

    def parse(self, data):
        self.revision = data.eat("L")
        self.algoHash = CryptoAlgo(data.eat("L"))
        self.rounds = data.eat("L")
        data.eat("L")
        self.algoCipher = CryptoAlgo(data.eat("L"))
        self.dataLen = data.eat("L")
        self.hmacLen = data.eat("L")
        self.iv = data.eat("16s")

        self.userSID = RPC_SID()
        self.userSID.parse(data)

        n = self.dataLen + self.hmacLen
        n += -n % self.algoCipher.blockSize
        self.encrypted = data.eat_string(n)
        
        self.revision2 = data.eat("L")
        self.guid = data.eat("16s")

    def decryptWithHash(self, h):

        sid = (self.userSID+"\0").encode("UTF-16LE")
        cleartxt = dataDecrypt(self.encrypted, h, sid, self.algoCipher,
                               self.iv, self.algoHash, self.rounds)
        self.password = cleartxt[:self.dataLen]
        self.hmac = cleartxt[self.dataLen:self.dataLen+16]

        ##TODO: Compute & Verify HMAC

    def decryptWithPassword(self, password):
        m = hashlib.sha1()
        m.update(password.encode("UTF-16LE"))
        return self.decryptWithHash(m.digest())

    def __repr__(self):
        s = ["""CredHist entry
        revision: %(revision)x
        hash: %(algoHash)r
        rounds: %(rounds)i
        cipher: %(algoCipher)r
        dataLen: %(dataLen)i
        hmacLen: %(hmacLen)i
        userSID: %(userSID)s""" % self.__dict__]
        s.append("\tiv: %s" % self.iv.encode("hex"))
        s.append("\tguid: %s" % self.guid.encode("hex"))
        if self.password is not None:
            s.append("\tpassword: %r %s" % (self.password, self.password.encode(hex)))
        if self.hmac is not None:
            s.append("\hmac: %r %s" % (self.hmac, self.hmac.encode(hex)))
        return "\n".join(s)


class CredHistPool(DataStruct):
    def __init__(self, raw=None):
        self.dico = dict()
        self.guid = dict()
        self.pool = []
        DataStruct.__init__(self, raw)

    def parse(self, data):
        while True:
            l = data.pop("L")
            if l == 0:
                break
            self.addEntry(data.pop_string(l-4))
        
        self.footmagic = data.eat("L")
        self.currpw = data.eat("16s")


    def addEntry(self, blob):
        x = CredhistEntry(blob)
        self.guid[x.guid] = x
        self.guid[x.guid.encode('hex')] = x
        self.pool.append(x)

    def lookupGUID(self, guid):
        if guid == self.currpw:
            return self.curhash
        if guid in self.guid:
            return self.guid[guid].hash
        return None

    def lookupHash(self, h):
        return self.dico.get(h)

    def addPassword(self, pwd):
        m = hashlib.sha1()
        m.update(pwd.encode("UTF-16LE"))
        self.dico[m.digest()] = pwd
        self.dico[m.hexdigest()] = pwd
        self.curhash = m.digest()

    def addWordlist(self, filename):
        for w in open(filename, "r"):
            self.addPassword(w.rstrip())
 
    def decryptWithHash(self, h):
        curhash = h
        for entry in self.pool:
            try:
                entry.decryptWithHash(curhash)
                curhash = entry.getHash()
                p = self.lookupHash(curhash)
                if p != None:
                    entry.setPassword(p)
            except Exception:
                return False
        return True

    def decryptWithPassword(self, pwd):
        m = hashlib.sha1()
        m.update(pwd.encode("UTF-16LE"))
        self.dico[m.digest()] = pwd
        self.dico[m.hexdigest()] = pwd
        return self.decryptWithHash(m.digest())

    def __repr__(self):
        return """CredHistPool:  %s
        pool = %r
        dico = %r""" % (self.currpw.encode('hex'), self.pool, self.dico)
    


# vim:ts=4:expandtab:sw=4
