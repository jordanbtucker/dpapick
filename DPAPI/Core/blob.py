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

from crypto import *
import hashlib
from M2Crypto import *
from eater import Eater, DataStruct

class DPAPIBlob(DataStruct):
    def __init__(self, raw=None):
        self.clearText = None
        self.decrypted = False
        self.crcComputed = None
        DataStruct.__init__(self, raw)

    def parse(self, data):
        self.version = data.eat("L")
        self.provider = "%0x-%0x-%0x-%0x%0x-%0x%0x%0x%0x%0x%0x" % data.eat("L2H8B")

        ## For HMAC computation
        blobStart = data.ofs

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
        self.strong = data.eat_length_and_string("L")
        self.hashAlgo = CryptoAlgo(data.eat("L"))
        self.hashLen = data.eat("L")
        self.salt = data.eat_length_and_string("L")
        self.cipherText = data.eat_length_and_string("L")

        ## For HMAC computation
        self.blob = data.raw[blobStart:data.ofs]

        self.crc = data.eat_length_and_string("L")


    def decrypt(self, masterkey, entropy=None, strongPassword=None):
        sessionkey = CryptSessionKey(masterkey, self.data, self.hashAlgo.name,
                                     entropy=entropy, strongPassword=strongPassword)
        keys = CryptDeriveKey(sessionkey, self.cipherAlgo, self.hashAlgo.name)
        cipher = EVP.Cipher(self.cipherAlgo.m2name, keys[:self.cipherAlgo.keyLength], 
                            "\x00"*self.cipherAlgo.ivLength, m2.decrypt, 0)
        cipher.set_padding(1)
        try:
            self.clearText = cipher.update(self.cipherText) + cipher.final()
        except:
            self.decrypted = False
            return

        ## check against provided HMAC
        self.crcComputed = CryptSessionKey(masterkey, self.salt, self.hashAlgo.name,
                                           entropy=entropy,
                                           strongPassword=self.blob)
        self.decrypted = self.crcComputed == self.crc

    def __repr__(self):
        s = ["DPAPI BLOB"]
        s.append("""        version     = %(version)d
        provider    = %(provider)s
        mkey        = %(guids)r
        flags       = %(flags)#x
        descr       = %(description)s
        cipherAlgo  = %(cipherAlgo)r
        hashAlgo    = %(hashAlgo)r""" % self.__dict__)
        s.append("\tdata        = %s" % self.data.encode('hex'))
        s.append("\tsalt        = %s" % self.salt.encode('hex'))
        s.append("\tcipher      = %s" % self.cipherText.encode('hex'))
        s.append("\tcrc         = %s" % self.crc.encode('hex'))
        if self.crcComputed is not None:
            s.append("\tcrcComputed = %s" % self.crcComputed.encode('hex'))
        if self.clearText is not None:
            s.append("\tcleartext   = %r" % self.clearText)
        return "\n".join(s)

# vim:ts=4:expandtab:sw=4
