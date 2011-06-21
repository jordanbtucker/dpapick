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

from crypto import *
import hashlib
from M2Crypto import *
from eater import Eater, DataStruct

class DPAPIBlob(DataStruct):
    def __init__(self, raw=None):
        self.clearText = None
        DataStruct.__init__(self, raw)

    def parse(self, data):
        self.version = data.eat("L")
        self.provider = "%0x-%0x-%0x-%0x%0x-%0x%0x%0x%0x%0x%0x" % data.eat("L2H8B")

        self.guids = []
        nb = data.eat("L")
        while nb > 0:
            p = data.eat("L2H8B")
            nb -= 1
            self.guids.append("%0x-%0x-%0x-%0x%0x-%0x%0x%0x%0x%0x%0x" % p)

        self.flags = data.eat("L")
        self.description = data.eat_length_and_string("L").decode("UTF-16LE")
        self.cipherAlgo = CryptoAlgo( data.eat("L") )
        self.keyLen = data.eat("L")
        self.data = data.eat_length_and_string("L")
        data.eat("L")
        self.hashAlgo = CryptoAlgo(data.eat("L"))
        self.hashLen = data.eat("L")
        self.salt = data.eat_length_and_string("L")
        self.cipherText = data.eat_length_and_string("L")
        self.crc = data.eat_length_and_string("L")


    def decrypt(self, masterkey, entropy=None, strongPassword=None):
        sessionkey = CryptSessionKey(masterkey, self.data, self.hashAlgo.name,
                                     entropy=entropy, strongPassword=strongPassword)
        keys = CryptDeriveKey(sessionkey, self.cipherAlgo, self.hashAlgo.name)
        cipher = EVP.Cipher(self.cipherAlgo.m2name, keys[:self.cipherAlgo.keyLength], 
                            "\x00"*self.cipherAlgo.ivLength, m2.decrypt, 0)
        cipher.set_padding(0)
        self.clearText = cipher.update(self.cipherText) + cipher.final()
        ##TODO: check against provided HMAC

    def __repr__(self):
        s = ["DPAPI BLOB"]
        s.append("""        version: %(version)d
        provider: %(provider)s
        mkey: %(guids)r
        flags: %(flags)#x
        descr: %(description)s
        cipherAlgo: %(cipherAlgo)r
        hashAlgo: %(hashAlgo)r""" % self.__dict__)
        s.append("\tdata: %s" % self.data.encode('hex'))
        s.append("\tsalt: %s" % self.salt.encode('hex'))
        s.append("\tcipher: %s" % self.cipherText.encode('hex'))
        s.append("\tcrc: %s" % self.crc.encode('hex'))
        if self.clearText is not None:
            s.append("\tcleartext: %r" % self.clearText)
        return "\n".join(s)

# vim:ts=4:expandtab:sw=4
