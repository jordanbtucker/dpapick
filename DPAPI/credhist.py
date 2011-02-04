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

class CredhistEntry:
    """Represents an entry in the Credhist file"""
    
    def __init__(self, raw):
        """Initialize the object with raw bytes"""
        self._raw = raw
        self._clear = None
        self.isParsed = False

    def setPassword(self, p):
        self._clear = p

    def parse(self):
        """Unpack the object and returns boolean wether it was successfull or not"""
        try:
            args = { "offset": 0, "fmt": "", "buffer": self._raw }
            args["fmt"] = "<7L"
            tmp = struct.unpack_from(args["fmt"], args["buffer"], args["offset"])
            args["offset"] += struct.calcsize(args["fmt"])
            self._magic = tmp[0]
            self._algoHash = CryptoAlgo(tmp[1])
            self._rounds = tmp[2]
            self._todo = tmp[3]
            self._algoCipher = CryptoAlgo(tmp[4])
            self._dataLen = tmp[5]
            self._hmacLen = tmp[6]

            args["fmt"] = "<%uB" % (self._todo)
            tmp = struct.unpack_from(args["fmt"], args["buffer"], args["offset"])
            args["offset"] += struct.calcsize(args["fmt"])
            self._iv = "".join(map(chr,tmp))

            args["fmt"] = "<4L"
            tmp = struct.unpack_from(args["fmt"], args["buffer"], args["offset"])
            args["offset"] += struct.calcsize(args["fmt"])
            self._dwUserId = tmp

            n = self._dataLen + self._hmacLen
            if n % self._algoCipher.blockSize() > 0:
                n = self._algoCipher.blockSize() * (n / self._algoCipher.blockSize() + 1)
            args["fmt"] = "<%uB" % (n)
            tmp = struct.unpack_from(args["fmt"], args["buffer"], args["offset"])
            args["offset"] += struct.calcsize(args["fmt"])
            self._encrypted = "".join(map(chr,tmp))

            args["fmt"] = "<L16BL"
            tmp = struct.unpack_from(args["fmt"], args["buffer"], args["offset"])
            args["offset"] += struct.calcsize(args["fmt"])
            self._magic2 = tmp[0]
            self._guid = "".join(map(chr,tmp[1:17]))
            self._size = tmp[-1]

        except Exception as e:
            self.isParsed = False
        else:
            self.isParsed = True
            self.isEncrypted = True
        finally:
            return self.isParsed

    def __repr__(self):
        d = {
            "guid": self._guid.encode('hex'),
            "magic": self._magic,
            "algo": self._algoHash,
            "rounds": self._rounds,
            "todo": self._todo,
            "cipher": self._algoCipher,
            "dataLen": self._dataLen,
            "hmacLen": self._hmacLen,
            "iv": self.getIV().encode('hex'),
            "userid": map(hex,self._dwUserId),
            "userSID": self.getUserSID(),
            "encrypted": self._encrypted.encode('hex'),
            "magic2": self._magic2,
            "entrysize": self._size,
            "data": "<ENCRYPTED>",
            "hmac": "<ENCRYPTED>",
            "password": ""
        }
        if self._clear != None:
            d["password"] = "'%s'" % (self._clear)
        if self.isEncrypted == False:
            d["data"] = self._password.encode('hex')
            d["hmac"] = self._hmac.encode('hex')
        if self.isParsed == True:
            return """
    CredHistEntry(%(guid)s): %(password)s
        dwMagic: %(magic)#x
        dwAlgoHash: %(algo)r
        dwRounds: %(rounds)#x
        dwTodo: %(todo)#x
        dwCipherAlgo: %(cipher)r
        dwDataLen: %(dataLen)#x
        dwHmacLen: %(hmacLen)#x
        bIV: %(iv)s
        dwUserId: %(userid)r
        UserSID: %(userSID)s
        bEncrypted: %(encrypted)s
        bData: %(data)s
        bHmac: %(hmac)s
        dwMagic2: %(magic2)#x
        bGUID: %(guid)s
        dwEntrySize: %(entrysize)u (%(entrysize)#x)
    """ % d
        else:
            return "CredHistEntry(RAW): %s" % (self._raw.encode('hex'))

    def getIV(self):
        if self.isParsed == True:
            return self._iv[:16]
        else:
            return None

    def getGUID(self):
        if self.isParsed == True:
            return self._guid
        else:
            return None

    def getUserSID(self):
        if self.isParsed == True:
            return "S-%d-%d-%d-%d-%d-%d-%d" % (
                    ord(self._iv[16]),
                    ord(self._iv[16+1]),
                    ord(self._iv[16+8]),
                    self._dwUserId[0],
                    self._dwUserId[1],
                    self._dwUserId[2],
                    self._dwUserId[3]
                    )
        else:
            return None

    def decryptWithHash(self, h):
        if self.isParsed == False:
            return False
        sid = self.getUserSID()
        sid += "\0"
        sid = sid.encode("UTF-16LE")
        cleartxt = dataDecrypt(self._encrypted,
                h, sid, self._algoCipher,
                self.getIV(), self._algoHash, self._rounds)
        self._password = cleartxt[:self._dataLen]
        self._hmac = cleartxt[self._dataLen:]
        self._hmac = self._hmac[:16]
        ##TODO: Compute & Verify HMAC
        self.isEncrypted = False
        return True

    def decryptWithPassword(self, password):
        m = hashlib.sha1()
        m.update(password.encode("UTF-16LE"))
        return self.decryptWithHash(m.digest())

    def getHash(self):
        if self.isEncrypted == True:
            return None
        else:
            return self._password

class CredHistPool:
    def __init__(self, raw):
        self._dico = dict()
        self._guid = dict()
        self._pool = []
        self._raw = raw

    def parse(self):
        total = len(self._raw)
        size = struct.unpack("<L", self._raw[-4:])
        while size[0] != 0:
            if size[0] > total:
                return False
            total -= size[0]
            self.addEntry(self._raw[total:])
            size = struct.unpack_from("<L", self._raw[total - struct.calcsize("<L"):])
        if total > 0:
            footer = struct.unpack_from("<L16BL", self._raw)
            self._currpw = ''.join(map(chr, footer[1:-1]))
            self._footMagic = footer[0]
        return True

    def addEntry(self, blob):
        x = CredhistEntry(blob)
        try:
            x.parse()
        except Exception:
            return False
        else:
            self._guid[x.getGUID()] = x
            self._guid[x.getGUID().encode('hex')] = x
            self._pool.append(x)
            return True

    def lookupGUID(self, guid):
        if guid == self._currpw:
            return self._curhash
        if guid in self._guid:
            return self._guid[guid].getHash()
        else:
            return None

    def lookupHash(self, h):
        if h in self._dico:
            return self._dico[h]
        else:
            return None

    def addPassword(self, pwd):
        m = hashlib.sha1()
        m.update(pwd.encode("UTF-16LE"))
        self._dico[m.digest()] = pwd
        self._dico[m.hexdigest()] = pwd
        self._curhash = m.digest()

    def addWordlist(self, filename):
        f = open(filename, "r")
        for w in f:
            self.addPassword(w.rstrip())
 
    def decryptWithHash(self, h):
        curhash = h
        for entry in self._pool:
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
        self._dico[m.digest()] = pwd
        self._dico[m.hexdigest()] = pwd
        return self.decryptWithHash(m.digest())

    def __repr__(self):
        return """
CredHistPool:
%s,
pool = %r,
dico = %r
""" % (self._currpw.encode('hex'), self._pool, self._dico)
    


# vim:ts=4:expandtab:sw=4
