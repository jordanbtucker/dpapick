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

import string
import crypto
import hashlib
from collections import defaultdict
from eater import Eater, DataStruct



class MasterKey(DataStruct):
    def __init__(self, raw=None):
        self.keyValue = None
        self.hmacSalt= None
        self.hmacValue = None
        self.hmacComputed = None
        self.decrypted = False
        DataStruct.__init__(self, raw)
        
    def parse(self, data):
        self.version = data.eat("L")
        self.salt = data.eat("16s")
        self.rounds = data.eat("L")
        self.macAlgo = crypto.CryptoAlgo(data.eat("L"))
        self.cipherAlgo = crypto.CryptoAlgo(data.eat("L"))
        self.encrypted = data.remain()

    def decryptWithHash(self, userSID, h):
        ## Compute encryption key
        userSID = userSID.upper()+"\0"
        userSID = userSID.encode("UTF-16LE")

        cleartxt = crypto.dataDecrypt(self.encrypted, h, userSID, self.cipherAlgo, 
                                      self.salt, self.macAlgo, self.rounds)

        self.keyValue = cleartxt[-64:]
        self.hmacSalt = cleartxt[:16]
        self.hmacValue = cleartxt[16:16+self.macAlgo.digestLength]
        self.hmacComputed = crypto.DpapiHmac(h, userSID, self.macAlgo,
                                             self.hmacSalt, self.keyValue)
        self.decrypted = self.hmacValue == self.hmacComputed

    def __repr__(self):
        s = ["  + Masterkey block"]
        s.append("        version\t= %i" % self.version)
        s.append("        salt\t= %s" % self.salt.encode("hex"))
        s.append("        rounds\t= %i" % self.rounds)
        s.append("        macalgo\t= %s" % repr(self.macAlgo))
        s.append("        cipheralgo\t= %s" % repr(self.cipherAlgo))
        if self.decrypted:
            s.append("        keyValue\t= %s" % self.keyValue.encode("hex"))
            s.append("        hmacSalt\t= %s" % self.hmacSalt.encode("hex"))
            s.append("        hmacValue\t= %s" % self.hmacValue.encode("hex"))
            s.append("        hmacComputed\t= %s" % self.hmacComputed.encode("hex"))
        else:
            s.append("        encrypted= %s" % self.encrypted.encode("hex"))
        return "\n".join(s)


class CredHist(DataStruct):
    def parse(self, data):
        self.magic = data.eat("L")
        self.guid = data.remain()
    def __repr__(self):
        s = ["  + CredHist block"]
        s.append("        magic\t= %(magic)d %(magic)#x" % self.__dict__)
        s.append("        guid\t= %s" % self.guid.encode("hex"))
        return "\n".join(s)

class DomainKey(DataStruct):
    def parse(self, data):
        self.version = data.eat("L")
        self.firstKeyLen = data.eat("L")
        self.secondKeyLen = data.eat("L")
        self.salt = data.eat("16s")
        self.firstKey = data.eat("%us" % self.firstKeyLen)
        self.secondKey = data.eat("%us" % self.secondKeyLen)
    def __repr__(self):
        s = ["  + DomainKey block"]
        s.append("        version\t= %x" % self.version)
        s.append("        salt\t= %x" % self.salt.encode("hex"))
        s.append("        firstKey\t= %x" % self.firstKey.encode("hex"))
        s.append("        secondKey\t= %x" % self.secondKey.encode("hex"))
        return "\n".join(s)

class MasterKeyFile(DataStruct):
    def __init__(self, raw=None):
        self.masterkey = None
        self.backupkey = None
        self.credhist = None
        self.domainkey = None
        self.decrypted = False
        DataStruct.__init__(self, raw)
        
    def parse(self, data):
        self.version = data.eat("L")
        data.eat("2L")
        self.keyGUID = data.eat("72s").decode("UTF-16LE")
        data.eat("2L")
        self.flags = data.eat("L")
        self.masterkeyLen = data.eat("Q")
        self.backupkeyLen = data.eat("Q")
        self.credhistLen = data.eat("Q")
        self.domainkeyLen = data.eat("Q")
        
        if self.masterkeyLen > 0:
            self.masterkey = MasterKey()
            self.masterkey.parse(data.eat_sub(self.masterkeyLen))
        if self.backupkeyLen > 0:
            self.backupkey = MasterKey()
            self.backupkey.parse(data.eat_sub(self.backupkeyLen))
        if self.credhistLen > 0:
            self.credhist = CredHist()
            self.credhist.parse(data.eat_sub(self.credhistLen))
        if self.domainkeyLen > 0:
            self.domainkey = Domainkey()
            self.domainkey.parse(data.eat_sub(self.domainkeyLen))

    def decryptWithPassword(self, userSID, pwd):
        return self.decryptWithHash(userSID, hashlib.sha1(pwd.encode("UTF-16LE")).digest())

    def decryptWithHash(self, userSID, h):
        self.masterkey.decryptWithHash(userSID, h)
        self.backupkey.decryptWithHash(userSID, h)
        self.decrypted = self.masterkey.decrypted or self.backupkey.decrypted
    
    def get_key(self):
        if self.masterkey.decrypted:
            return self.masterkey.keyValue
        elif self.backupkey.decrypted:
            return self.backupkey.keyValue
        

    def __repr__(self):
        s = ["\n#### MasterKeyFile %s ####" % self.keyGUID]
        s.append("""        dwVersion: %(version)#x
        dwFlags: %(flags)#x
        cbMasterKey: %(masterkeyLen)d (%(masterkeyLen)#x)
        cbBackupKey: %(backupkeyLen)d (%(backupkeyLen)#x)
        cbCredHist: %(credhistLen)d (%(credhistLen)#x)
        cbDomainKey: %(domainkeyLen)d (%(domainkeyLen)#x)""" % self.__dict__)
        if self.masterkey:
            s.append(repr(self.masterkey))
        if self.backupkey:
            s.append(repr(self.backupkey))
        if self.credhist:
            s.append(repr(self.credhist))
        if self.domainkey:
            s.append(repr(self.domainkey))
        return "\n".join(s)


class MasterKeyPool:
    def __init__(self):
        self.users = defaultdict(lambda: {})
        self.keys = defaultdict(lambda: [])

    def addMasterKey(self, raw, userSID="S-1-5-18"):
        userSID = userSID.upper()
        mkey = MasterKeyFile(raw)
        self.users[userSID][mkey.keyGUID] = mkey
        self.keys[mkey.keyGUID].append(mkey)

    def getMasterKey(self, keyGUID, userSID="S-1-5-18"):
        userSID = userSID.upper()
        if keyGUID in self.keys:
            if len(self.keys[keyGUID]) == 1:
                return self.keys[keyGUID][0]
            if userSID in self.users and keyGUID in self.users[userSID]:
                return self.users[userSID][keyGUID]
        return None

    def __repr__(self):
        return """
        MasterKeyPool:
        dict = %r
        keys = %r
        """ % (self.users.items(), self.keys.items())

# vim:ts=4:expandtab:sw=4
