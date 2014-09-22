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


class MkeyXPTest(unittest.TestCase):
    def setUp(self):
        self.mkeyblob = ("02000000000000000000000039006600"
            "6200360034003400320066002d003600"
            "3200360061002d003400390038003000"
            "2d0039006300380035002d0064003200"
            "33003800620065003900350035006200"
            "33006300000000000000000005000000"
            "88000000000000006800000000000000"
            "14000000000000000000000000000000"
            "02000000a3e410b7f9a8f942e9a9b439"
            "157c35dea00f00000980000003660000"
            "b817f2201ab33dbc2199cd72694243cb"
            "eda34ce8ad2306dd23308ba537e7967b"
            "e2303701ab9f6a4f8d23fdd922f609ef"
            "b276c47fcebc0321cf73ac50e8b6702d"
            "5b079d96bb09c605cd0fda93a1db4b41"
            "337c5b41d360da11f792540ace642265"
            "b600007173dbba9a02000000d43b01cc"
            "0590035e567e07b44b6ccead01000000"
            "098000000366000095bb351da2ee8c44"
            "63c5092a931feba5613f7bbf1570ecde"
            "fd887d5bae9dc18fa95724c1976c2201"
            "2fae9cdbf6f70c4aaab721b9a87e17d7"
            "25d9dd110f9339777df1b807c90af31a"
            "030000008c0cc86717255245ba9544f8"
            "8914bc13").decode("hex")
        self.mk = masterkey.MasterKeyFile(self.mkeyblob)
        self.sid = "S-1-5-21-583907252-1547161642-682003330-1001"
        self.password = "tutu"
        self.pwdhash = "8fd090d6121b0f67ebb58bce562bf02b3f1e6bb4".decode("hex")

    def test_parsing(self):
        self.assertEqual(self.mk.version, 2)
        self.assertEqual(self.mk.masterkey.cipherAlgo.algnum, 0x6603)
        self.assertEqual(self.mk.masterkey.hashAlgo.algnum, 0x8009)
        self.assertFalse(self.mk.masterkey.decrypted)
        self.assertEqual(len(self.mk.masterkey.ciphertext), 104)

    def test_decrypt_bad_password(self):
        self.mk.decryptWithPassword(self.sid, "badpassword")

        self.assertFalse(self.mk.decrypted)
        self.assertFalse(self.mk.masterkey.decrypted)

    def test_decrypt_good_password(self):
        self.mk.decryptWithPassword(self.sid, self.password)

        self.assertTrue(self.mk.masterkey.decrypted)
        self.assertTrue(self.mk.decrypted)
        self.assertEqual(self.mk.masterkey.hmac, self.mk.masterkey.hmacComputed)
        self.assertEqual(len(self.mk.masterkey.iv), 16)
        self.assertEqual(len(self.mk.masterkey.key), 64)
        self.assertEqual(len(self.mk.masterkey.hmacSalt), 16)

    def test_decrypt_with_hash(self):
        self.assertFalse(self.mk.decrypted)
        self.mk.decryptWithHash(self.sid, self.pwdhash)

        self.assertTrue(self.mk.masterkey.decrypted)
        self.assertTrue(self.mk.decrypted)
        self.assertEqual(self.mk.masterkey.hmac, self.mk.masterkey.hmacComputed)
        self.assertEqual(len(self.mk.masterkey.iv), 16)
        self.assertEqual(len(self.mk.masterkey.key), 64)
        self.assertEqual(len(self.mk.masterkey.hmacSalt), 16)


class MkeyWin7Test(unittest.TestCase):
    pass


if __name__ == "__main__":
    unittest.main()

