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

import unittest
from DPAPI.Core import crypto


class CryptoAlgoTest(unittest.TestCase):
    def test_unknown_algo(self):
        self.assertRaises(KeyError, crypto.CryptoAlgo, 0)

    def test_des3(self):
        alg = crypto.CryptoAlgo(0x6603)

        with self.assertRaises(AttributeError):
            _ = alg.digestLength
        self.assertEquals(alg.keyLength, 24)
        self.assertEquals(alg.name, "DES3")
        self.assertEquals(alg.m2name, "des_ede3_cbc")
        self.assertEquals(alg.ivLength, 8)
        self.assertEquals(alg.blockSize, 8)

    def test_sha512(self):
        alg = crypto.CryptoAlgo(0x800e)

        with self.assertRaises(AttributeError):
            _ = alg.keyLength
            _ = alg.ivLength
            _ = alg.m2name
        self.assertEquals(alg.name, "sha512")
        self.assertEquals(alg.digestLength, 64)
        self.assertEquals(alg.blockSize, 128)


class CryptoTest(unittest.TestCase):
    def test_CryptSessionKey(self):
        pass

    def test_CryptDeriveKey(self):
        pass

    def test_decrypt_lsa_key(self):
        pass

    def test_SystemFunction005(self):
        pass

    def test_pbkdf2(self):
        pass

    def test_derivePwdHash(self):
        pass

    def test_derivePassword(self):
        pass

    def test_dataDecrypt(self):
        pass

    def test_DPAPIHmac(self):
        pass


if __name__ == "__main__":
    unittest.main()
