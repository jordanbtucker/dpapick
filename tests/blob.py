#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ############################################################################
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
        self.assertEqual(len(self.blob.salt), 16)
        self.assertEqual(len(self.blob.hmac), 16)
        self.assertEqual(len(self.blob.strong), 0)
        self.assertEqual(len(self.blob.cipherText), 24)
        self.assertEqual(len(self.blob.sign), 20)

    def test_decrypt_bad_key(self):
        self.blob.decrypt("", None, None)

        self.assertFalse(self.blob.decrypted)

    def test_decrypt_good_key_bad_entropy(self):
        self.blob.decrypt(self.mkey, "fake", None)

        self.assertFalse(self.blob.decrypted)

    def test_decrypt_good_key_good_entropy(self):
        self.blob.decrypt(self.mkey, None, None)

        self.assertTrue(self.blob.decrypted)
        self.assertEqual(self.blob.sign, self.blob.signComputed)
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
        self.assertEqual(len(self.blob.salt), 16)
        self.assertEqual(len(self.blob.hmac), 16)
        self.assertEqual(len(self.blob.strong), 0)
        self.assertEqual(len(self.blob.cipherText), 32)
        self.assertEqual(len(self.blob.sign), 20)

    def test_decrypt_bad_key(self):
        self.blob.decrypt("", None, None)

        self.assertFalse(self.blob.decrypted)

    def test_decrypt_good_key_bad_entropy(self):
        self.blob.decrypt(self.mkey, None, None)

        self.assertFalse(self.blob.decrypted)

    def test_decrypt_good_key_good_entropy(self):
        self.blob.decrypt(self.mkey, self.entropy, None)

        self.assertTrue(self.blob.decrypted)
        self.assertEqual(self.blob.sign, self.blob.signComputed)
        self.assertEqual(self.blob.cleartext, "This entropy was not faked")


class BlobWin8SimpleTest(unittest.TestCase):
    def setUp(self):
        self.raw = ("01000000d08c9ddf0115d1118c7a00c0"
                    "4fc297eb010000003fb376ba974b974e"
                    "96037865fb972cec0000000002000000"
                    "00001066000000010000200000009798"
                    "683005ff678f507036b44bcbbcfe1501"
                    "15346bf67bd75ad73b42ce6331bf0000"
                    "00000e800000000200002000000040da"
                    "71bec41e2cf971d270977099e1d34030"
                    "f0875de802967769f7b4906cbc951000"
                    "00005ccee1467028df028177bda3c9c3"
                    "40574000000045fb9275a0e852ed4b9f"
                    "2e34ec6100bb2d3bd5225da37bccb73b"
                    "fb89b4073dc215840c8beeb728201ab6"
                    "9a41945c944cf6ae645d2e69d00b752c"
                    "a1552b42ed3d").decode("hex")
        self.mkey = ("c942b584a88a36f3ce8abe61a62d4036"
                     "49dfdd8fd9b256a4a7ff64bfe2b60df8"
                     "cb563be71d0d65f8be03ebdd76b4dba1"
                     "68a9e3883fee758d2c4aeef040571cc2").decode("hex")
        self.blob = blob.DPAPIBlob(self.raw)

    def test_parsing(self):
        self.assertEqual(self.blob.version, 1)
        self.assertEqual(self.blob.provider, "df9d8cd0-1501-11d1-8c7a-00c04fc297eb")
        self.assertEqual(self.blob.cipherAlgo.algnum, 0x6610)
        self.assertEqual(self.blob.hashAlgo.algnum, 0x800e)
        self.assertEqual(self.blob.description, "\x00")
        self.assertFalse(self.blob.decrypted)
        self.assertEqual(len(self.blob.salt), 32)
        self.assertEqual(len(self.blob.hmac), 32)
        self.assertEqual(len(self.blob.strong), 0)
        self.assertEqual(len(self.blob.cipherText), 16)
        self.assertEqual(len(self.blob.sign), 64)

    def test_decrypt_bad_key(self):
        self.blob.decrypt("", None, None)

        self.assertFalse(self.blob.decrypted)

    def test_decrypt_good_key_bad_entropy(self):
        self.blob.decrypt(self.mkey, "fake", None)

        self.assertFalse(self.blob.decrypted)

    def test_decrypt_good_key_good_entropy(self):
        self.blob.decrypt(self.mkey, None, None)

        self.assertTrue(self.blob.decrypted)
        self.assertEqual(self.blob.sign, self.blob.signComputed)
        self.assertEqual(self.blob.cleartext, "UberSecret\x00")


class BlobWin8EntropyTest(unittest.TestCase):
    def setUp(self):
        self.raw = ("01000000d08c9ddf0115d1118c7a00c0"
                    "4fc297eb010000003fb376ba974b974e"
                    "96037865fb972cec0000000044000000"
                    "7000770064003a006600750066006600"
                    "61003b00200065006e00740072006f00"
                    "70007900280061007300630069006900"
                    "29003d005500700054006f0041007000"
                    "70000000106600000001000020000000"
                    "600ed99a7cba8250b56e6571a852a435"
                    "ba30522905fc6f297c2f5a31d6b7fa45"
                    "000000000e8000000002000020000000"
                    "dc2539884092c76194a57bbf090e94dc"
                    "ec850a23f03afcef723de96b6b1a4638"
                    "10000000d747986bfd422553f30c8fb1"
                    "265e1365400000003c4236133cc43d41"
                    "6ed650106e0f980de4c58e5db4513ea0"
                    "605207b0835ac69c2c95f3b5b26511c4"
                    "4543a996b390952689843a20dbbaa209"
                    "e6440b74ff02c49c").decode("hex")
        self.mkey = ("c942b584a88a36f3ce8abe61a62d4036"
                     "49dfdd8fd9b256a4a7ff64bfe2b60df8"
                     "cb563be71d0d65f8be03ebdd76b4dba1"
                     "68a9e3883fee758d2c4aeef040571cc2").decode("hex")
        self.blob = blob.DPAPIBlob(self.raw)
        self.entropy = "UpToApp\x00"

    def test_parsing(self):
        self.assertEqual(self.blob.version, 1)
        self.assertEqual(self.blob.provider, "df9d8cd0-1501-11d1-8c7a-00c04fc297eb")
        self.assertEqual(self.blob.cipherAlgo.algnum, 0x6610)
        self.assertEqual(self.blob.hashAlgo.algnum, 0x800e)
        self.assertEqual(self.blob.description, "pwd:fuffa; entropy(ascii)=UpToApp\x00")
        self.assertFalse(self.blob.decrypted)
        self.assertEqual(len(self.blob.salt), 32)
        self.assertEqual(len(self.blob.hmac), 32)
        self.assertEqual(len(self.blob.strong), 0)
        self.assertEqual(len(self.blob.cipherText), 16)
        self.assertEqual(len(self.blob.sign), 64)

    def test_decrypt_bad_key(self):
        self.blob.decrypt("")

        self.assertFalse(self.blob.decrypted)

    def test_decrypt_good_key_bad_entropy(self):
        self.blob.decrypt(self.mkey)

        self.assertFalse(self.blob.decrypted)

    def test_decrypt_good_key_good_entropy(self):
        self.blob.decrypt(self.mkey, self.entropy)

        self.assertTrue(self.blob.decrypted)
        self.assertEqual(self.blob.sign, self.blob.signComputed)
        self.assertEqual(self.blob.cleartext, "UberSecret\x00")


if __name__ == "__main__":
    unittest.main()

