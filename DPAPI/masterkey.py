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

class MasterKey:

    def __init__(self, raw):
        self._raw = raw
        self.isParsed = False

    def getGUID(self):
        if self.isParsed == True:
            return self._keyGUID
        return None

    def getCredhistGUID(self):
        if self._credHist != None:
            return self._credHist["guid"]
        return None

    def getValue(self):
        if self._masterkey != None:
            if self._masterkey["isEncrypted"] == False:
                return self._masterkey["keyValue"]
        return None

    def decryptWithHash(self, h, userSID):
        ## Compute encryption key
        userSID += "\x00"
        userSID = userSID.encode("UTF-16LE")

        ## Masterkey
        if self._masterkey != None:
            cleartxt = dataDecrypt(
                    self._masterkey["encrypted"],
                    h,
                    userSID,
                    self._masterkey["cipherAlgo"],
                    self._masterkey["salt"],
                    self._masterkey["macAlgo"],
                    self._masterkey["rounds"])
            self._masterkey["keyValue"] = cleartxt[-64:]
            self._masterkey["hmacSalt"] = cleartxt[:16]
            hmacValue = cleartxt[16:]
            hmacValue = hmacValue[:self._masterkey["macAlgo"].digestLength()]
            self._masterkey["hmacValue"] = hmacValue
            self._masterkey["hmacComputed"] = DpapiHmac(h, userSID,
                    self._masterkey["macAlgo"],
                    self._masterkey["hmacSalt"],
                    self._masterkey["keyValue"])
            self._masterkey["isEncrypted"] = False

        ## BackupKey
        ## TODO: seems to use a different scheme...
        if self._backupkey != None:
            cleartxt = dataDecrypt(
                    self._backupkey["encrypted"],
                    h,
                    userSID,
                    self._backupkey["cipherAlgo"],
                    self._backupkey["salt"],
                    self._backupkey["macAlgo"],
                    self._backupkey["rounds"])
            self._backupkey["keyValue"] = cleartxt
            self._backupkey["hmacSalt"] = ""
            self._backupkey["hmacValue"] = ""
            self._backupkey["hmacComputed"] = "" #DpapiHmac(h, userSID,
    #                self._backupkey["macAlgo"],
    #                self._backupkey["hmacSalt"],
    #                self._backupkey["keyValue"])
            self._backupkey["isEncrypted"] = False

        ## DomainKey
        #TODO
        if self._domainkey != None:
            cleartxt = dataDecrypt(
                    self._domainkey["encrypted"],
                    h,
                    userSID,
                    self._domainkey["cipherAlgo"],
                    self._domainkey["salt"],
                    self._domainkey["macAlgo"],
                    self._domainkey["rounds"])
            self._domainkey["keyValue"] = cleartxt
            self._domainkey["hmacSalt"] = ""
            self._domainkey["hmacValue"] = ""
            self._domainkey["hmacComputed"] = "" #DpapiHmac(h, userSID,
#                    self._domainkey["macAlgo"],
#                    self._domainkey["hmacSalt"],
#                    self._domainkey["keyValue"])
            self._domainkey["isEncrypted"] = False

        return True

    def compareHMAC(self):
        if self._masterkey == None:
            return False
        if "hmacValue" not in self._masterkey:
            return False
        if "hmacComputed" not in self._masterkey:
            return False
        if len(self._masterkey["hmacComputed"]) < 10:
            return False
        return self._masterkey["hmacValue"] == self._masterkey["hmacComputed"]

    def decryptWithPassword(self, pwd, userSID):
        if self.isParsed == False:
            return False
        if self._masterkey["isEncrypted"] == False:
            return True
        return self.decryptWithHash(hashlib.sha1(pwd.encode("UTF-16LE")).digest(), userSID)

    def parse(self):
        try:
            args = { "offset": 0, "fmt": "", "buffer": self._raw }

            ## Header
            args["fmt"] = "<3L36H3L4Q"
            tmp = struct.unpack_from(args["fmt"], args["buffer"], args["offset"])
            args["offset"] += struct.calcsize(args["fmt"])

            self._version = tmp[0]
            self._keyGUID = tmp[3:39]
            self._domainkeyLen = tmp[-1]
            self._credHistLen = tmp[-2]
            self._backupkeyLen = tmp[-3]
            self._masterkeyLen = tmp[-4]
            self._masterkey = None
            self._backupkey = None
            self._credHist = None
            self._domainkey = None
            self._flags = tmp[-5]

            if self._masterkeyLen > 0:
                ## Masterkey block
                args["fmt"] = "<L16B3L%uB" % (self._masterkeyLen - struct.calcsize("<L16B3L"))
                tmp = struct.unpack_from(args["fmt"], args["buffer"], args["offset"])
                args["offset"] += struct.calcsize(args["fmt"])

                self._masterkey = dict()
                self._masterkey["version"] = tmp[0]
                self._masterkey["salt"] = "".join(map(chr, tmp[1:17]))
                self._masterkey["rounds"] = tmp[17]
                self._masterkey["macAlgo"] = CryptoAlgo(tmp[18])
                self._masterkey["cipherAlgo"] = CryptoAlgo(tmp[19])
                self._masterkey["encrypted"] = "".join(map(chr, tmp[20:]))
                self._masterkey["isEncrypted"] = True
                self._masterkey["keyValue"] = '<ENCRYPTED>'
                self._masterkey["hmacSalt"] = "<ENCRYPTED>"
                self._masterkey["hmacValue"] = "<ENCRYPTED>"
                self._masterkey["hmacComputed"] = "<ENCRYPTED>"

            if self._backupkeyLen > 0:
                ## Backupkey block
                args["fmt"] = "<L16B3L%uB" % (self._backupkeyLen - struct.calcsize("<L16B3L"))
                tmp = struct.unpack_from(args["fmt"], args["buffer"], args["offset"])
                args["offset"] += struct.calcsize(args["fmt"])

                self._backupkey = dict()
                self._backupkey["version"] = tmp[0]
                self._backupkey["salt"] = "".join(map(chr, tmp[1:17]))
                self._backupkey["rounds"] = tmp[17]
                self._backupkey["macAlgo"] = CryptoAlgo(tmp[18])
                self._backupkey["cipherAlgo"] = CryptoAlgo(tmp[19])
                self._backupkey["encrypted"] = "".join(map(chr, tmp[20:]))
                self._backupkey["isEncrypted"] = True
                self._backupkey["keyValue"] = '<ENCRYPTED>'
                self._backupkey["hmacSalt"] = "<ENCRYPTED>"
                self._backupkey["hmacValue"] = "<ENCRYPTED>"
                self._backupkey["hmacComputed"] = "<ENCRYPTED>"

            if self._credHistLen > 0:
                ## Credhist GUID block
                args["fmt"] = "<L%uB" % (self._credHistLen - struct.calcsize("<L"))
                tmp = struct.unpack_from(args["fmt"], args["buffer"], args["offset"])
                args["offset"] += struct.calcsize(args["fmt"])

                self._credHist = dict()
                self._credHist["magic"] = tmp[0]
                self._credHist["guid"] = "".join(map(chr, tmp[1:]))

            if self._domainkeyLen > 0:
                ## Domainkey block
                args["fmt"] = "<L16B3L%uB" % (self._domainkeyLen)
                tmp = struct.unpack_from(args["fmt"], args["buffer"], args["offset"])
                args["offset"] += struct.calcsize(args["fmt"])

                self._domainkey = dict()
                self._domainkey["version"] = tmp[0]
                self._domainkey["salt"] = "".join(tmp[1:17])
                self._domainkey["rounds"] = tmp[17]
                self._domainkey["macAlgo"] = CryptoAlgo(tmp[18])
                self._domainkey["cipherAlgo"] = CryptoAlgo(tmp[19])
                self._domainkey["encrypted"] = "".join(map(chr, tmp[20:]))
                self._domainkey["isEncrypted"] = True
                self._domainkey["keyValue"] = '<ENCRYPTED>'
                self._domainkey["hmacSalt"] = "<ENCRYPTED>"
                self._domainkey["hmacValue"] = "<ENCRYPTED>"
                self._domainkey["hmacComputed"] = "<ENCRYPTED>"

        except Exception as e:
            self.isParsed = False
        else:
            self.isParsed = True
        finally:
            return self.isParsed

    def __repr__(self):
        if self.isParsed == False:
            return """
            MasterKey(RAW): %s""" % (self._raw.encode('hex'))
        else:
            d = {
                    "version": self._version,
                    "guid": "".join(map(chr, self._keyGUID)),
                    "flags": self._flags,
                    "mkeyLen": self._masterkeyLen,
                    "bkLen": self._backupkeyLen,
                    "credhistLen": self._credHistLen,
                    "domainLen": self._domainkeyLen
                    }
            tplstr = """
            MasterKey(%(guid)s):
                dwVersion: %(version)#x
                szGUID: %(guid)s
                dwFlags: %(flags)#x
                cbMasterKey: %(mkeyLen)d (%(mkeyLen)#x)
                cbBackupKey: %(bkLen)d (%(bkLen)#x)
                cbCredHist: %(credhistLen)d (%(credhistLen)#x)
                cbDomainKey: %(domainLen)d (%(domainLen)#x)""" % d

            if self._masterkey != None:
                args = self._masterkey.copy()
                args["salt"] = args["salt"].encode('hex')
                args["encrypted"] = args["encrypted"].encode('hex')
                if args["isEncrypted"] == False:
                    args["hmacSalt"] = args["hmacSalt"].encode('hex')
                    args["hmacValue"] = args["hmacValue"].encode('hex')
                    args["hmacComputed"] = args["hmacComputed"].encode('hex')
                    args["keyValue"] = args["keyValue"].encode('hex')

                tplstr += """

                MasterKey Block
                    dwBlockType: %(version)#x
                    bSalt: %(salt)s
                    cbIteration: %(rounds)d (%(rounds)#x)
                    MACAlgo: %(macAlgo)r
                    CipherAlgo: %(cipherAlgo)r
                    bCipheredKey: %(encrypted)s
                    decryptedKey: %(keyValue)s
                    hmacSalt: %(hmacSalt)s
                    hmacValue: %(hmacValue)s
                    hmacComputed: %(hmacComputed)s""" % args

            if self._backupkey != None:
                args = self._backupkey.copy()
                args["salt"] = args["salt"].encode('hex')
                args["encrypted"] = args["encrypted"].encode('hex')
                if args["isEncrypted"] == False:
                    args["hmacSalt"] = args["hmacSalt"].encode('hex')
                    args["hmacValue"] = args["hmacValue"].encode('hex')
                    args["hmacComputed"] = args["hmacComputed"].encode('hex')
                    args["keyValue"] = args["keyValue"].encode('hex')

                tplstr += """

                BackupKey Block
                    dwBlockType: %(version)#x
                    bSalt: %(salt)s
                    cbIteration: %(rounds)d (%(rounds)#x)
                    MACAlgo: %(macAlgo)r
                    CipherAlgo: %(cipherAlgo)r
                    bCipheredKey: %(encrypted)s
                    decryptedKey: %(keyValue)s
                    hmacSalt: %(hmacSalt)s
                    hmacValue: %(hmacValue)s
                    hmacComputed: %(hmacComputed)s""" % args

            if self._credHist != None:
                args = self._credHist.copy()
                args["guid"] = args["guid"].encode("hex")

                tplstr += """

                CredHist:
                    dwBlockType: %(magic)d (%(magic)#x)
                    bCredHistGUID: %(guid)s""" % args

            if self._domainkey != None:
                args = self._domainkey.copy()
                args["salt"] = args["salt"].encode('hex')
                args["encrypted"] = args["encrypted"].encode('hex')
                if args["isEncrypted"] == False:
                    args["hmacSalt"] = args["hmacSalt"].encode('hex')
                    args["hmacValue"] = args["hmacValue"].encode('hex')
                    args["hmacComputed"] = args["hmacComputed"].encode('hex')
                    args["keyValue"] = args["keyValue"].encode('hex')

                tplstr += """

                DomainKey Block
                    dwBlockType: %(version)#x
                    bSalt: %(salt)s
                    cbIteration: %(rounds)d (%(rounds)#x)
                    MACAlgo: %(macAlgo)r
                    CipherAlgo: %(cipherAlgo)r
                    bCipheredKey: %(encrypted)s
                    decryptedKey: %(keyValue)s
                    hmacSalt: %(hmacSalt)s
                    hmacValue: %(hmacValue)s
                    hmacComputed: %(hmacComputed)s""" % args

            return tplstr

class MasterKeyPool:
    def __init__(self):
        self._dict = dict()
        self._keys = dict()

    def addMasterKey(self, raw, userSID="S-1-5-20"):
        if userSID not in self._dict:
            self._dict[userSID] = dict()
        mkey = MasterKey(raw)
        if mkey.parse() == True:
            keyID = "".join(map(chr, mkey.getGUID()))
            self._dict[userSID][keyID] = mkey
            if keyID in self._keys:
                self._keys[keyID].append(mkey)
            else:
                self._keys[keyID] = [ mkey ]
            return True
        return False

    def getMasterKey(self, keyGUID, userSID="S-1-5-20"):
        if keyGUID in self._keys:
            if len(self._keys[keyGUID]) == 1:
                return self._keys[keyGUID][0]
            if userSID in self._dict and keyGUID in self._dict[userSID]:
                return self._dict[userSID][keyGUID]
            print "Eh merde..."
        return None

    def __repr__(self):
        return """
        MasterKeyPool:
        dict = %r
        keys = %r
        """ % (self._dict, self._keys)

# vim:ts=4:expandtab:sw=4
