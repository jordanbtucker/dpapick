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
from DPAPI.Core import masterkey
from DPAPI.Core import crypto
from DPAPI.Core import blob


class BlobXPSimpleTest(unittest.TestCase):
    def setUp(self):
        self.raw = ("01000000d08c9ddf0115d1118c7a00c0"
            "4fc297eb010000002f44b69f6a628049"
            "9c85d238be955b3c000000003c000000"
            "4400500041005000490063006b002000"
            "730069006d0070006c00650020006200"
            "6c006f0062002000670065006e006500"
            "7200610074006f007200000003660000"
            "a80000001000000055d9d46709e463db"
            "53c783ec1edd69dc0000000004800000"
            "a00000001000000038d39c66910558b6"
            "a4e961b5de40e84918000000eae8acdd"
            "f984a8efae7701754baf9f844c9f1cbd"
            "df818a9f14000000be5c65c109be3c7f"
            "d4787df81e923b596f635d0f").decode("hex")
        self.mkey = ("f1cd9c3915428d12c0e9bf5ac0c44dda"
            "647e6e387118c09eb00a294e485a3f6e"
            "fe47f16686ad5f60fbd740164de87711"
            "6eb70d35445b22ddebdb02b0d55ee613").decode("hex")
        self.blob = blob.DPAPIBlob(self.raw)

    def test_parsing(self):
        self.assertEqual(self.blob.version, 1)
        self.assertEqual(self.blob.provider, "df9d8cd0-1501-11d1-8c7a-00c04fc297eb")
        self.assertEqual(self.blob.cipherAlgo.algnum, 0x6603)
        self.assertEqual(self.blob.hashAlgo.algnum, 0x8004)
        self.assertEqual(self.blob.description, "DPAPIck simple blob generator\x00")
        self.assertFalse(self.blob.decrypted)
        self.assertEqual(len(self.blob.data), 16)
        self.assertEqual(len(self.blob.salt), 16)
        self.assertEqual(len(self.blob.strong), 0)
        self.assertEqual(len(self.blob.cipherText), 24)
        self.assertEqual(len(self.blob.crc), 20)

    def test_decrypt_bad_key(self):
        self.blob.decrypt("", None, None)

        self.assertFalse(self.blob.decrypted)

    def test_decrypt_good_key_bad_entropy(self):
        self.blob.decrypt(self.mkey, "fake", None)

        self.assertFalse(self.blob.decrypted)

    def test_decrypt_good_key_good_entropy(self):
        self.blob.decrypt(self.mkey, None, None)

        self.assertTrue(self.blob.decrypted)
        self.assertEqual(self.blob.crc, self.blob.crcComputed)
        self.assertEqual(self.blob.cleartext, "This is for real !")


class BlobXPEntropyTest(unittest.TestCase):
    def setUp(self):
        self.raw = ("01000000d08c9ddf0115d1118c7a00c0"
            "4fc297eb0100000018fa1d263223e549"
            "93d9388d2f271486000000003c000000"
            "4400500041005000490063006b002000"
            "730069006d0070006c00650020006200"
            "6c006f0062002000670065006e006500"
            "7200610074006f007200000003660000"
            "a8000000100000000c1e54f10d3ac713"
            "ef4c19dbc440e4a70000000004800000"
            "a000000010000000bde7c0f3b1d5def7"
            "cbb6669c2c2b361c2000000062658248"
            "66ed719fe25046d193bf6fd8252be099"
            "ac10609b50677b57ea61bbbf14000000"
            "5906ca660b04e0c1bce743ebe5b21aa9"
            "e79acc1f").decode("hex")
        self.mkey = ("d0c624a61e4080ac28ec07f33466581ec"
            "04980f26953aa940258dc4ced7fd5452"
            "51208d88d6bac5c64b5cd69b4e214009"
            "3174f51ab07f0f5fb7a45462a2c00e4").decode("hex")
        self.blob = blob.DPAPIBlob(self.raw)
        self.entropy = "toto123"

    def test_parsing(self):
        self.assertEqual(self.blob.version, 1)
        self.assertEqual(self.blob.provider, "df9d8cd0-1501-11d1-8c7a-00c04fc297eb")
        self.assertEqual(self.blob.cipherAlgo.algnum, 0x6603)
        self.assertEqual(self.blob.hashAlgo.algnum, 0x8004)
        self.assertEqual(self.blob.description, "DPAPIck simple blob generator\x00")
        self.assertFalse(self.blob.decrypted)
        self.assertEqual(len(self.blob.data), 16)
        self.assertEqual(len(self.blob.salt), 16)
        self.assertEqual(len(self.blob.strong), 0)
        self.assertEqual(len(self.blob.cipherText), 32)
        self.assertEqual(len(self.blob.crc), 20)

    def test_decrypt_bad_key(self):
        self.blob.decrypt("", None, None)

        self.assertFalse(self.blob.decrypted)

    def test_decrypt_good_key_bad_entropy(self):
        self.blob.decrypt(self.mkey, None, None)

        self.assertFalse(self.blob.decrypted)

    def test_decrypt_good_key_good_entropy(self):
        self.blob.decrypt(self.mkey, self.entropy, None)

        self.assertTrue(self.blob.decrypted)
        self.assertEqual(self.blob.crc, self.blob.crcComputed)
        self.assertEqual(self.blob.cleartext, "This entropy was not faked")


class BlobWin8SimpleTest(unittest.TestCase):
    def setUp(self):
        self.raw = ("").decode("hex")
        self.mkey = ("").decode("hex")
        self.blob = blob.DPAPIBlob(self.raw)

    def test_parsing(self):
        self.assertEqual(self.blob.version, 1)
        self.assertEqual(self.blob.provider, "df9d8cd0-1501-11d1-8c7a-00c04fc297eb")
        self.assertEqual(self.blob.cipherAlgo.algnum, 0x6610)
        self.assertEqual(self.blob.hashAlgo.algnum, 0x800e)
        self.assertEqual(self.blob.description, "DPAPIck simple blob generator\x00")
        self.assertFalse(self.blob.decrypted)
        self.assertEqual(len(self.blob.data), 16)
        self.assertEqual(len(self.blob.salt), 16)
        self.assertEqual(len(self.blob.strong), 0)
        self.assertEqual(len(self.blob.cipherText), 24)
        self.assertEqual(len(self.blob.crc), 20)

    def test_decrypt_bad_key(self):
        self.blob.decrypt("", None, None)

        self.assertFalse(self.blob.decrypted)

    def test_decrypt_good_key_bad_entropy(self):
        self.blob.decrypt(self.mkey, "fake", None)

        self.assertFalse(self.blob.decrypted)

    def test_decrypt_good_key_good_entropy(self):
        self.blob.decrypt(self.mkey, None, None)

        self.assertTrue(self.blob.decrypted)
        self.assertEqual(self.blob.crc, self.blob.crcComputed)
        self.assertEqual(self.blob.cleartext, "This is for real !")


class BlobWin8EntropyTest(unittest.TestCase):
    def setUp(self):
        self.raw = ("").decode("hex")
        self.mkey = ("").decode("hex")
        self.blob = blob.DPAPIBlob(self.raw)
        self.entropy = "toto123"

    def test_parsing(self):
        self.assertEqual(self.blob.version, 1)
        self.assertEqual(self.blob.provider, "df9d8cd0-1501-11d1-8c7a-00c04fc297eb")
        self.assertEqual(self.blob.cipherAlgo.algnum, 0x6610)
        self.assertEqual(self.blob.hashAlgo.algnum, 0x800e)
        self.assertEqual(self.blob.description, "DPAPIck simple blob generator\x00")
        self.assertFalse(self.blob.decrypted)
        self.assertEqual(len(self.blob.data), 16)
        self.assertEqual(len(self.blob.salt), 16)
        self.assertEqual(len(self.blob.strong), 0)
        self.assertEqual(len(self.blob.cipherText), 32)
        self.assertEqual(len(self.blob.crc), 20)

    def test_decrypt_bad_key(self):
        self.blob.decrypt("", None, None)

        self.assertFalse(self.blob.decrypted)

    def test_decrypt_good_key_bad_entropy(self):
        self.blob.decrypt(self.mkey, None, None)

        self.assertFalse(self.blob.decrypted)

    def test_decrypt_good_key_good_entropy(self):
        self.blob.decrypt(self.mkey, self.entropy, None)

        self.assertTrue(self.blob.decrypted)
        self.assertEqual(self.blob.crc, self.blob.crcComputed)
        self.assertEqual(self.blob.cleartext, "This entropy was not faked")


if __name__ == "__main__":
    unittest.main()

