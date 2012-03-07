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

import struct
import string
import hashlib
from M2Crypto import *
import crypto
from eater import Eater, DataStruct


class RPC_SID(DataStruct):
    """Represents a RPC_SID structure. See MSDN for documentation"""
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
    """This represents the DPAPI_SYSTEM token which is stored as an LSA
        secret.

        Sets 2 properties:
            self.machine
            self.user

    """
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

    def decryptWithKey(self, enckey):
        """Decrypts this credhist entry using the given encryption key."""
        cleartxt = crypto.dataDecrypt(self.cipherAlgo, self.hashAlgo, self.encrypted, 
                                      enckey, self.iv, self.rounds)
        self.pwdhash = cleartxt[:self.dataLen]
        self.hmac = cleartxt[self.dataLen:self.dataLen+self.hmacLen]
        ##TODO: Compute & Verify HMAC. Dunno if it's possible...

    def decryptWithHash(self, pwdhash):
        """Decrypts this credhist entry with the given user's password hash.
        Simply computes the encryption key with the given hash then calls
        self.decryptWithKey() to finish the decryption.

        """
        self.decryptWithKey(crypto.derivePwdHash(pwdhash, str(self.userSID),
            self.hashAlgo))

    def decryptWithPassword(self, password):
        """Decrypts this credhist entry with the given user's password.
        Simply computes the password hash then calls self.decryptWithHash()

        """
        return self.decryptWithHash(hashlib.sha1(password.encode("UTF-16LE")).digest())

    def jtr_shadow(self):
        """Returns a string that can be passed to John the Ripper to crack this
            CREDHIST entry. Requires to use a recent jumbo version of JtR plus
            the configuration snipplet in the "3rdparty" directory of DPAPIck.

            Unless you know what you are doing, you shall not call this function
            yourself. Instead, use the method provided by CredHistPool object.
        """
        if self.pwdhash is not None:
            return "%s:$dynamic_1400$%s" % (self.userSID, self.pwdhash.encode('hex'))
        return ""

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
    """Represents a CREDHIST file.
    Be aware that currently, it is not possible to check whether the decryption
    succeeded or not. To circumvent that and optimize a little bit crypto
    operations, once a credhist entry successfully decrypts a masterkey, the
    whole CredHistFile is flagged as valid. Then, no further decryption occurs.
    
    """

    def __init__(self, raw=None):
        self.entries_list = []
        self.entries = {}
        self.valid = False
        
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
        """Creates a CredhistEntry object with blob then adds it to the store"""
        x = CredhistEntry(blob)
        self.entries[x.guid] = x
        self.entries_list.append(x)
 
    def validate(self):
        """Simply flags a file as successfully decrypted. See the class
        documentation for information.
        
        """
        self.valid = True

    def decryptWithHash(self, h):
        """Try to decrypt each entry with the given hash"""
        if self.valid == True:
            return
        curhash = h
        for entry in self.entries_list:
            entry.decryptWithHash(curhash)
            curhash = entry.pwdhash

    def decryptWithPassword(self, pwd):
        """Try to decrypt each entry with the given password.
        This function simply computes the SHA-1 hash with the password, then
        calls self.decryptWithHash()

        """
        return self.decryptWithHash(hashlib.sha1(pwd.encode("UTF-16LE")).digest())

    def jtr_shadow(self, validonly=False):
        """Returns a string that can be passed to John the Ripper to crack the
            CREDHIST entries. Requires to use a recent jumbo version of JtR plus
            the configuration snipplet in the "3rdparty" directory of DPAPIck.

            If validonly is set to True, will only extract CREDHIST entries
            that are known to have sucessfully decrypted a masterkey.

        """
        if validonly and not self.valid:
            return ""
        s = []
        for e in self.entries.itervalues():
            s.append(e.jtr_shadow())
        return "\n".join(s)

    def __repr__(self):
        s = ["CredHistPool:  %s" % self.curr_guid]
        for e in self.entries.itervalues():
            s.append("---")
            s.append(repr(e))
        s.append("====")
        return "\n".join(s)
    

# vim:ts=4:expandtab:sw=4
