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

    def test_decrypt_with_key(self):
        self.assertFalse(self.mk.decrypted)
        self.mk.decryptWithKey(crypto.derivePwdHash(self.pwdhash, self.sid))

        self.assertTrue(self.mk.masterkey.decrypted)
        self.assertTrue(self.mk.decrypted)
        self.assertEqual(self.mk.masterkey.hmac, self.mk.masterkey.hmacComputed)
        self.assertEqual(len(self.mk.masterkey.iv), 16)
        self.assertEqual(len(self.mk.masterkey.key), 64)
        self.assertEqual(len(self.mk.masterkey.hmacSalt), 16)

    def test_decrypt_twice(self):
        self.assertFalse(self.mk.decrypted)
        self.mk.decryptWithHash(self.sid, self.pwdhash)

        self.assertTrue(self.mk.decrypted)
        self.mk.decryptWithHash(self.sid, "")
        self.assertTrue(self.mk.decrypted)

    def test_unpickle_pickle(self):
        self.maxDiff = None
        mkp = masterkey.MasterKeyPool()
        mkp.addMasterKey(self.mkeyblob)
        mkp2 = masterkey.MasterKeyPool.unpickle(data=mkp.pickle())

        self.assertNotEquals(len(mkp.getMasterKeys(self.mk.guid)), 0)
        self.assertNotEquals(len(mkp2.getMasterKeys(self.mk.guid)), 0)
        self.assertEquals(len(mkp.getMasterKeys(self.mk.guid)), len(mkp2.getMasterKeys(self.mk.guid)))
        self.assertEquals(repr(mkp.getMasterKeys(self.mk.guid)), repr(mkp2.getMasterKeys(self.mk.guid)))

    def test_unpickle_pickle_decrypted(self):
        self.maxDiff = None
        mkp = masterkey.MasterKeyPool()
        mkp.addMasterKey(self.mkeyblob)
        nb = mkp.try_credential(self.sid, self.password)
        mkp2 = masterkey.MasterKeyPool.unpickle(data=mkp.pickle())

        self.assertEquals(nb, 1)
        self.assertNotEquals(len(mkp.getMasterKeys(self.mk.guid)), 0)
        self.assertNotEquals(len(mkp2.getMasterKeys(self.mk.guid)), 0)
        self.assertEquals(len(mkp.getMasterKeys(self.mk.guid)), len(mkp2.getMasterKeys(self.mk.guid)))
        self.assertEquals(repr(mkp.getMasterKeys(self.mk.guid)), repr(mkp2.getMasterKeys(self.mk.guid)))


class MkeyWin7Test(unittest.TestCase):
    def setUp(self):
        self.mkeyblob = ("02000000000000000000000033003900"
            "3800370035006300610062002d003500"
            "3000330036002d003400610062006100"
            "2d0062003900650065002d0033003100"
            "62003500650031003600390066006500"
            "38003700000000000000000005000000"
            "b0000000000000009000000000000000"
            "14000000000000000000000000000000"
            "020000001f63ff38751365ec54748b13"
            "d962698ee01500000e80000010660000"
            "ac23e4d5efcb8979f05fbcb275832a8d"
            "ee9576fbaae76a4de7ead2f313e84bf7"
            "e4be7940b49319463c8cd25a1b4a67c1"
            "5adfbb02e2bbe42c24cd44bec3b9740b"
            "45ebcce3a2ef2788867c28168bf93ea0"
            "48844897f2854df5ac4eb000f72c3a6f"
            "25c65d5347e73c77120cfc3150c87e57"
            "52a017510c1486e71a9d0c32b79f333f"
            "2d0cda0ecc20774cbed8ca071aab9768"
            "02000000498e70c2ad3a4e7f9dd07340"
            "b86207bbe01500000e80000010660000"
            "e99ec2b15a0304ea208c0fc2bd9d655f"
            "e4c2ab86a275e51bb39ada495f2e9944"
            "fd9d8e3d74a00603b329f41706d0fb41"
            "0059ac25b98d7bbd46ae0f23e364216a"
            "9cb2733ff767f0f4a24958e7651e7dfb"
            "332521b34b69e118a8db203230a74f65"
            "3c01cec9489cc288ed617fb0de0d2ad0"
            "03000000a31ddfe1cf99304093caf6eb"
            "8b9c7b09").decode("hex")
        self.mk = masterkey.MasterKeyFile(self.mkeyblob)
        self.sid = "S-1-5-21-2421538757-1605280464-2344517820-1000"
        self.password = "fuffa"
        self.pwdhash = "74b87ba1e12734f71fe4737990e2c420bd145bf4".decode("hex")

    def test_parsing(self):
        self.assertEqual(self.mk.version, 2)
        self.assertEqual(self.mk.masterkey.cipherAlgo.algnum, 0x6610)
        self.assertEqual(self.mk.masterkey.hashAlgo.algnum, 0x800e)
        self.assertFalse(self.mk.masterkey.decrypted)
        self.assertEqual(len(self.mk.masterkey.ciphertext), 144)

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


class MkeyWin81Test(unittest.TestCase):
    def setUp(self):
        self.mkeyblob = ("02000000000000000000000062006100"
            "3700360062003300330066002d003400"
            "6200390037002d003400650039003700"
            "2d0039003600300033002d0037003800"
            "36003500660062003900370032006300"
            "6500630000007cb7e903000005000000"
            "b0000000000000009000000000000000"
            "14000000000000000000000000000000"
            "0200000020995cbe3eaa8e2926a4174d"
            "87189d3d401f00000e80000010660000"
            "6922ccc4b45562151d459760086b0baa"
            "5a87a3c039429d2dc3dbd638a71d244b"
            "595e4e49cff9e15fe9283be65e9e79e0"
            "128094838128aed0a909d80f9e8ae8f9"
            "431d9a585d2ff69c8a9165cd975e668b"
            "c43128b1d5712d814f1785b372249115"
            "e421a46a33acc1640aaeb0e151edfc8f"
            "c1ea836e270d50b49e1d8de3fb63b662"
            "7ff6b7b46e2eb7cbc5150eff0659b18f"
            "0200000083eb71d412c5a696d3219c84"
            "9ffbd397401f00000e80000010660000"
            "5e199aa472c0e1a8f816587c6ce54595"
            "0740c72690081e7f8526ef54b39a3c49"
            "39406b102ae289d6d05d43f8d94087f1"
            "56da548864394063ea5f6c895469b253"
            "9498e6be99351a2cb9b4b3e3714583f5"
            "20711e62f0b685c7cb1300f21b0a22bc"
            "a1f24852ac9292f475d56c936a1792c6"
            "03000000c70c2de2b511dc418f40ed80"
            "4bbf6a17").decode("hex")
        self.mk = masterkey.MasterKeyFile(self.mkeyblob)
        self.sid = "S-1-5-21-2128076315-4144300488-3078399761-1001"
        self.password = "fuffa"
        self.pwdhash = "74b87ba1e12734f71fe4737990e2c420bd145bf4".decode("hex")

    def test_parsing(self):
        self.assertEqual(self.mk.version, 2)
        self.assertEqual(self.mk.masterkey.cipherAlgo.algnum, 0x6610)
        self.assertEqual(self.mk.masterkey.hashAlgo.algnum, 0x800e)
        self.assertFalse(self.mk.masterkey.decrypted)
        self.assertEqual(len(self.mk.masterkey.ciphertext), 144)

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


if __name__ == "__main__":
    unittest.main()

