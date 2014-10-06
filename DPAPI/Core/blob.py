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
##  Author: Jean-Michel Picod <jmichel.p@gmail.com>                        ##
##                                                                         ##
## This program is distributed under GPLv3 licence (see LICENCE.txt)       ##
##                                                                         ##
#############################################################################

import M2Crypto
from DPAPI.Core import crypto
from DPAPI.Core import eater


class DPAPIBlob(eater.DataStruct):
    """Represents a DPAPI blob"""

    def __init__(self, raw=None):
        """Constructs a DPAPIBlob. If raw is set, automatically calls
            parse().

        """
        self.cleartext = None
        self.decrypted = False
        self.crcComputed = None
        eater.DataStruct.__init__(self, raw)

    def parse(self, data):
        """Parses the given data. May raise exceptions if incorrect data are
            given. You should not call this function yourself; DataStruct does

            data is a DataStruct object.
            Returns nothing.

        """
        self.version = data.eat("L")
        self.provider = "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x" % data.eat("L2H8B")

        ## For HMAC computation
        blobStart = data.ofs

        self.guids = []
        nb = data.eat("L")
        while nb > 0:
            p = data.eat("L2H8B")
            nb -= 1
            self.guids.append("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x" % p)

        self.flags = data.eat("L")
        self.description = data.eat_length_and_string("L").decode("UTF-16LE").encode("utf-8")
        self.cipherAlgo = crypto.CryptoAlgo( data.eat("L") )
        self.keyLen = data.eat("L")
        self.data = data.eat_length_and_string("L")
        self.strong = data.eat_length_and_string("L")
        self.hashAlgo = crypto.CryptoAlgo(data.eat("L"))
        self.hashLen = data.eat("L")
        self.salt = data.eat_length_and_string("L")
        self.cipherText = data.eat_length_and_string("L")

        ## For HMAC computation
        self.blob = data.raw[blobStart:data.ofs]

        self.crc = data.eat_length_and_string("L")

    def decrypt(self, masterkey, entropy=None, strongPassword=None):
        """Try to decrypt the blob. Returns True/False"""
        sessionkey = crypto.CryptSessionKey(masterkey, self.data, self.hashAlgo, entropy=entropy,
                                            strongPassword=strongPassword)
        keys = crypto.CryptDeriveKey(sessionkey, self.cipherAlgo, self.hashAlgo)
        cipher = M2Crypto.EVP.Cipher(self.cipherAlgo.m2name, keys[:self.cipherAlgo.keyLength],
                                     "\x00" * self.cipherAlgo.ivLength, M2Crypto.decrypt, 0)
        cipher.set_padding(1)
        try:
            self.cleartext = cipher.update(self.cipherText) + cipher.final()
        except:
            self.decrypted = False
            return False

        ## check against provided HMAC
        self.crcComputed = crypto.CryptSessionKey(masterkey, self.salt, self.hashAlgo, entropy=entropy,
                                                  strongPassword=self.blob)
        self.decrypted = self.crcComputed == self.crc
        return self.decrypted

    def __repr__(self):
        s = ["DPAPI BLOB"]
        s.append("\n".join(["\tversion     = %(version)d",
            "\tprovider    = %(provider)s",
            "\tmkey        = %(guids)r",
            "\tflags       = %(flags)#x",
            "\tdescr       = %(description)s",
            "\tcipherAlgo  = %(cipherAlgo)r",
            "\thashAlgo    = %(hashAlgo)r"]) % self.__dict__)
        s.append("\tdata        = %s" % self.data.encode('hex'))
        s.append("\tsalt        = %s" % self.salt.encode('hex'))
        s.append("\tcipher      = %s" % self.cipherText.encode('hex'))
        s.append("\tcrc         = %s" % self.crc.encode('hex'))
        if self.crcComputed is not None:
            s.append("\tcrcComputed = %s" % self.crcComputed.encode('hex'))
        if self.cleartext is not None:
            s.append("\tcleartext   = %r" % self.cleartext)
        return "\n".join(s)

# vim:ts=4:expandtab:sw=4
