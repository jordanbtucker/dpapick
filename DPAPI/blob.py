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

class DpapiBlob:
    def __init__(self, raw):
        self._raw = raw
        self.isParsed = False
        self.isEncrypted = True

    def decrypt(self, masterkey, entropy = "", strongPassword = ""):
        if self.isParsed == False:
            return False
        if self.isEncrypted == False:
            return True

        ## First compute the weird HMAC...
        digest = hashlib.new(self._hashAlgo.str())
        if len(masterkey) > 63:
            digest.update(masterkey)
            masterkey = digest.digest()
            digest = hashlib.new(self._hashAlgo.str())
        ipad = "\x36" * len(masterkey)
        opad = "\x5C" * len(masterkey)
        ipad = "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(masterkey, ipad)])
        opad = "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(masterkey, opad)])
        if len(ipad) < 64:
            ipad = ipad + "\x36" * (64 - len(ipad))
        if len(opad) < 64:
            opad = opad + "\x5C" * (64 - len(opad))
        digest.update(ipad)
        digest.update(self._data)
        tmp = digest.digest()
        digest = hashlib.new(self._hashAlgo.str())
        digest.update(opad)
        digest.update(tmp)
        if entropy != None and len(entropy) > 0:
            digest.update(entropy)
        if strongPassword != None and len(strongPassword) > 0:
            digest.update(strongPassword)

        ## Derive keys from it
        keys = CryptDeriveKey(digest.digest(), self._hashAlgo.str())

        ## Decrypt
        cipher = EVP.Cipher(self._cipherAlgo.m2name(), keys[:self._cipherAlgo.keyLength()], "\x00" * self._cipherAlgo.ivLength(), m2.decrypt, 0)
        cipher.set_padding(0)
        cleartext = cipher.update(self._cipherText)
        cipher.final()

        ##TODO: check against provided HMAC
        self._clearText = cleartext
        self.isEncrypted = False
        return True

    def getMasterkeyGUID(self):
        return self._keysGUID[0]

    def getCleartext(self):
        if self.isEncrypted == True:
            return None
        return self._clearText

    def parse(self):
        try:
            args = { "offset": 0, "fmt": "", "buffer": self._raw }

            ## Crypto providers
            args["fmt"] = "<L"
            tmp = struct.unpack_from(args["fmt"], args["buffer"], args["offset"])
            args["offset"] += struct.calcsize(args["fmt"])
            self._providers = []
            for i in range(0, tmp[0]):
                args["fmt"] = "<L2H8B"
                tmp = struct.unpack_from(args["fmt"], args["buffer"], args["offset"])
                args["offset"] += struct.calcsize(args["fmt"])
                self._providers.append("%0x-%0x-%0x-%0x%0x-%0x%0x%0x%0x%0x%0x" % tmp)

            ## Keys GUID
            args["fmt"] = "<L"
            tmp = struct.unpack_from(args["fmt"], args["buffer"], args["offset"])
            args["offset"] += struct.calcsize(args["fmt"])
            self._keysGUID = []
            for i in range(0, tmp[0]):
                args["fmt"] = "<L2H8B"
                tmp = struct.unpack_from(args["fmt"], args["buffer"], args["offset"])
                args["offset"] += struct.calcsize(args["fmt"])
                self._keysGUID.append("%0x-%0x-%0x-%0x%0x-%0x%0x%0x%0x%0x%0x" % tmp)

            ## Description
            args["fmt"] = "<2L"
            tmp = struct.unpack_from(args["fmt"], args["buffer"], args["offset"])
            args["offset"] += struct.calcsize(args["fmt"])
            self._flags = tmp[0]
            self._descrLen = tmp[1]

            args["fmt"] = "<%dH" % (tmp[1] / 2)
            tmp = struct.unpack_from(args["fmt"], args["buffer"], args["offset"])
            args["offset"] += struct.calcsize(args["fmt"])
            self._description = "".join(map(chr, tmp))

            args["fmt"] = "<3L"
            tmp = struct.unpack_from(args["fmt"], args["buffer"], args["offset"])
            args["offset"] += struct.calcsize(args["fmt"])
            self._cipherAlgo = CryptoAlgo(tmp[0])
            self._keyLen = tmp[1]
            self._dataLen = tmp[2]

            args["fmt"] = "<%dB" % (self._dataLen)
            tmp = struct.unpack_from(args["fmt"], args["buffer"], args["offset"])
            args["offset"] += struct.calcsize(args["fmt"])
            self._data = "".join(map(chr, tmp))

            args["fmt"] = "<4L"
            tmp = struct.unpack_from(args["fmt"], args["buffer"], args["offset"])
            args["offset"] += struct.calcsize(args["fmt"])
            self._hashAlgo = CryptoAlgo(tmp[1])
            self._hashLen = tmp[2]
            self._saltLen = tmp[3]

            args["fmt"] = "<%dB" % (self._saltLen)
            tmp = struct.unpack_from(args["fmt"], args["buffer"], args["offset"])
            args["offset"] += struct.calcsize(args["fmt"])
            self._salt = "".join(map(chr, tmp))

            args["fmt"] = "<L"
            tmp = struct.unpack_from(args["fmt"], args["buffer"], args["offset"])
            args["offset"] += struct.calcsize(args["fmt"])
            self._cipherLen = tmp[0]

            args["fmt"] = "<%dB" % (self._cipherLen)
            tmp = struct.unpack_from(args["fmt"], args["buffer"], args["offset"])
            args["offset"] += struct.calcsize(args["fmt"])
            self._cipherText = "".join(map(chr, tmp))

            args["fmt"] = "<L"
            tmp = struct.unpack_from(args["fmt"], args["buffer"], args["offset"])
            args["offset"] += struct.calcsize(args["fmt"])
            self._crcLen = tmp[0]

            args["fmt"] = "<%dB" % (self._crcLen)
            tmp = struct.unpack_from(args["fmt"], args["buffer"], args["offset"])
            args["offset"] += struct.calcsize(args["fmt"])
            self._crc = "".join(map(chr, tmp))

        except Exception as e:
            self.isParsed = False
        else:
            self.isParsed = True
            self.isEncrypted = True
        finally:
            self._clearText = None
            return self.isParsed

    def __repr__(self):
        if self.isParsed == False:
            return """
            DPAPI Blob (RAW): %s""" % self._raw.encode('hex')
        else:
            args = {
                    "providers": self._providers,
                    "mkey": self._keysGUID,
                    "flags": self._flags,
                    "descr": self._description,
                    "cipherAlgo": self._cipherAlgo,
                    "keyLen": self._keyLen,
                    "dataLen": self._dataLen,
                    "data": self._data.encode('hex'),
                    "hashAlgo": self._hashAlgo,
                    "hashLen": self._hashLen,
                    "saltLen": self._saltLen,
                    "salt": self._salt.encode('hex'),
                    "cipherLen": self._cipherLen,
                    "cipher": self._cipherText.encode('hex'),
                    "crcLen": self._crcLen,
                    "crc": self._crc.encode('hex'),
                    "clearText": "<ENCRYPTED>"
                    }
            if self.isEncrypted == False:
                args["clearText"] = self._clearText.encode('hex')
            return """
            DPAPI Blob:
                Providers: %(providers)r
                Masterkey GUID: %(mkey)r
                Flags: %(flags)d (%(flags)#x)
                Description: "%(descr)s"
                CipherAlgo: %(cipherAlgo)r
                KeyLen: %(keyLen)d (%(keyLen)#x)
                DataLen: %(dataLen)d (%(dataLen)#x)
                Data: %(data)s
                HashAlgo: %(hashAlgo)r
                HashLen: %(hashLen)d (%(hashLen)#x)
                SaltLen: %(saltLen)d (%(saltLen)#x)
                Salt: %(salt)s
                CipherLen: %(cipherLen)d (%(cipherLen)#x)
                Cipher: %(cipher)s
                CrcLen: %(crcLen)d (%(crcLen)#x)
                Crc: %(crc)s
                ClearText: %(clearText)s
                """ % args

# vim:ts=4:expandtab:sw=4
