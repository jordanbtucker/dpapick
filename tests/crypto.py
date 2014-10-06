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
    def setUp(self):
        self.pwd = "tutu"
        self.sid = "S-1-5-21-583907252-1547161642-682003330-1001"
        self.expected = "732f73394364c930ba285063e5ff1ae49ebb3332".decode("hex")
        self.hashpwd = "8fd090d6121b0f67ebb58bce562bf02b3f1e6bb4".decode("hex")

    def test_CryptSessionKeyXP(self):
        m = ("f1cd9c3915428d12c0e9bf5ac0c44dda"
            "647e6e387118c09eb00a294e485a3f6e"
            "fe47f16686ad5f60fbd740164de87711"
            "6eb70d35445b22ddebdb02b0d55ee613").decode("hex")
        n = "55d9d46709e463db53c783ec1edd69dc".decode("hex")
        h = "sha1"
        r = "397ec5c4dc5d5733b7dadd94178f827951b5ea66".decode("hex")

        self.assertEquals(crypto.CryptSessionKey(m, n, h), r)

    def test_CryptSessionKeyXPEntropy(self):
        m = ("d0c624a61e4080ac28ec07f33466581e"
            "c04980f26953aa940258dc4ced7fd545"
            "251208d88d6bac5c64b5cd69b4e21400"
            "93174f51ab07f0f5fb7a45462a2c00e4").decode("hex")
        n = "0c1e54f10d3ac713ef4c19dbc440e4a7".decode("hex")
        h = "sha1"
        e = "746f746f313233".decode("hex")
        r = "9e0ee9a096bcd43c315a211dc7fdb1fd1a01cbec".decode("hex")

        self.assertEquals(crypto.CryptSessionKey(m, n, h, e), r)

    def test_CryptSessionKeyXPStrong(self):
        m = ("f1cd9c3915428d12c0e9bf5ac0c44dda"
            "647e6e387118c09eb00a294e485a3f6e"
            "fe47f16686ad5f60fbd740164de87711"
            "6eb70d35445b22ddebdb02b0d55ee613").decode("hex")
        n = "38d39c66910558b6a4e961b5de40e849".decode("hex")
        h = "sha1"
        s = ("010000002f44b69f6a6280499c85d238"
            "be955b3c000000003c00000044005000"
            "41005000490063006b00200073006900"
            "6d0070006c006500200062006c006f00"
            "62002000670065006e00650072006100"
            "74006f007200000003660000a8000000"
            "1000000055d9d46709e463db53c783ec"
            "1edd69dc0000000004800000a0000000"
            "1000000038d39c66910558b6a4e961b5"
            "de40e84918000000eae8acddf984a8ef"
            "ae7701754baf9f844c9f1cbddf818a9f").decode("hex")
        r = "be5c65c109be3c7fd4787df81e923b596f635d0f".decode("hex")

        self.assertEquals(crypto.CryptSessionKey(m, n, h, None, s), r)

    def test_CryptSessionKeyXPEntropyStrong(self):
        m = ("d0c624a61e4080ac28ec07f33466581e"
            "c04980f26953aa940258dc4ced7fd545"
            "251208d88d6bac5c64b5cd69b4e21400"
            "93174f51ab07f0f5fb7a45462a2c00e4").decode("hex")
        n = "bde7c0f3b1d5def7cbb6669c2c2b361c".decode("hex")
        h = "sha1"
        e = "746f746f313233".decode("hex")
        s = ("0100000018fa1d263223e54993d9388d2"
            "f271486000000003c0000004400500041"
            "005000490063006b002000730069006d0"
            "070006c006500200062006c006f006200"
            "2000670065006e0065007200610074006"
            "f007200000003660000a8000000100000"
            "000c1e54f10d3ac713ef4c19dbc440e4a"
            "70000000004800000a000000010000000"
            "bde7c0f3b1d5def7cbb6669c2c2b361c2"
            "00000006265824866ed719fe25046d193"
            "bf6fd8252be099ac10609b50677b57ea6"
            "1bbbf").decode("hex")
        r = "5906ca660b04e0c1bce743ebe5b21aa9e79acc1f".decode("hex")

        self.assertEquals(crypto.CryptSessionKey(m, n, h, e, s), r)

    def test_CryptDeriveKeyWin8(self):
        return
        h = "".decode("hex")
        c = crypto.CryptoAlgo(0x6603)
        r = "".decode("hex")

        self.assertEquals(crypto.CryptDeriveKey(), r)

    def test_CryptDeriveKeyXP(self):
        h = "9e0ee9a096bcd43c315a211dc7fdb1fd1a01cbec".decode("hex")
        c = crypto.CryptoAlgo(0x6610)
        r = ("e41a0d8b93243370b3722699588a83b2"
            "28b533d82e609a6932bb2f9899be9a4a"
            "f06a5a420963de45").decode("hex")

        self.assertEquals(crypto.CryptDeriveKey(h, c), r)

    def test_decrypt_lsa_key(self):
        pass

    def test_SystemFunction005(self):
        pass

    def test_pbkdf2_1round_sha1(self):
        # XP
        p = "732f73394364c930ba285063e5ff1ae49ebb3332"
        s = "2dd1662578e68d982e18f362452d448a"
        i = 1
        r = "b49f149f5dca24e46025fcc2fb8af8a6a19c849c7b61fcc5533c841f6eb10d8b"
        self.assertEquals(crypto.pbkdf2(p.decode("hex"), s.decode("hex"), len(r) / 2, i), r.decode('hex'))

    def test_pbkdf2_4000round_sha1(self):
        # XP
        p = "732f73394364c930ba285063e5ff1ae49ebb3332"
        s = "a432a7fe84cc5ff921eddfb645d22efc"
        i = 4000
        r = "0cb271e155eb6fd2f9c50e1c941a248d4a1d8b1cb765e0cdb8f80e144d3dfb03"
        self.assertEquals(crypto.pbkdf2(p.decode("hex"), s.decode("hex"), len(r) / 2, i), r.decode('hex'))

    def test_pbkdf2_5600round_sha512(self):
        # win7
        p = "84e40ab5bab2c5a2965fd185d60cf92fe2c1c9d2".decode("hex")
        s = "1f63ff38751365ec54748b13d962698e".decode("hex")
        i = 5600
        r = ("38d34e6a81f8d5f650403d01407e3127"
            "f987f986328ed9c1aacd527811dd53ac"
            "5a7b8d298e37e377daa03a3ee209e638").decode("hex")
        self.assertEquals(crypto.pbkdf2(p, s, len(r), i, 'sha512'), r)

    def test_derivePwdHash(self):
        #TODO: add error cases
        self.assertEquals(crypto.derivePwdHash(self.hashpwd, self.sid), self.expected)

    def test_derivePassword(self):
        #TODO: add error cases
        self.assertEquals(crypto.derivePassword(self.pwd, self.sid), self.expected)

    def test_dataDecrypt(self):
        pass

    def test_DPAPIHmac(self):
        pass


if __name__ == "__main__":
    unittest.main()
