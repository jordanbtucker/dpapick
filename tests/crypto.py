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
        h = crypto.CryptoAlgo(0x8004)
        r = "397ec5c4dc5d5733b7dadd94178f827951b5ea66".decode("hex")

        self.assertEquals(crypto.CryptSessionKeyXP(m, n, h), r)
        self.assertEquals(crypto.CryptSessionKeyWin7(m, n, h), r)

    def test_CryptSessionKeyXPEntropy(self):
        m = ("d0c624a61e4080ac28ec07f33466581e"
             "c04980f26953aa940258dc4ced7fd545"
             "251208d88d6bac5c64b5cd69b4e21400"
             "93174f51ab07f0f5fb7a45462a2c00e4").decode("hex")
        n = "0c1e54f10d3ac713ef4c19dbc440e4a7".decode("hex")
        h = crypto.CryptoAlgo(0x8004)
        e = "746f746f313233".decode("hex")
        r = "9e0ee9a096bcd43c315a211dc7fdb1fd1a01cbec".decode("hex")

        self.assertEquals(crypto.CryptSessionKeyXP(m, n, h, e), r)
        self.assertNotEquals(crypto.CryptSessionKeyWin7(m, n, h, e), r)

    def test_CryptSessionKeyXPStrong(self):
        m = ("f1cd9c3915428d12c0e9bf5ac0c44dda"
             "647e6e387118c09eb00a294e485a3f6e"
             "fe47f16686ad5f60fbd740164de87711"
             "6eb70d35445b22ddebdb02b0d55ee613").decode("hex")
        n = "38d39c66910558b6a4e961b5de40e849".decode("hex")
        h = crypto.CryptoAlgo(0x8004)
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

        self.assertEquals(crypto.CryptSessionKeyXP(m, n, h, None, s), r)
        self.assertNotEquals(crypto.CryptSessionKeyWin7(m, n, h, None, s), r)

    def test_CryptSessionKeyXPEntropyStrong(self):
        m = ("d0c624a61e4080ac28ec07f33466581e"
             "c04980f26953aa940258dc4ced7fd545"
             "251208d88d6bac5c64b5cd69b4e21400"
             "93174f51ab07f0f5fb7a45462a2c00e4").decode("hex")
        n = "bde7c0f3b1d5def7cbb6669c2c2b361c".decode("hex")
        h = crypto.CryptoAlgo(0x8004)
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

        self.assertEquals(crypto.CryptSessionKeyXP(m, n, h, e, s), r)
        self.assertNotEquals(crypto.CryptSessionKeyWin7(m, n, h, e, s), r)

    def test_CryptSessionKeyWin81(self):
        m = ("c942b584a88a36f3ce8abe61a62d4036"
             "49dfdd8fd9b256a4a7ff64bfe2b60df8"
             "cb563be71d0d65f8be03ebdd76b4dba1"
             "68a9e3883fee758d2c4aeef040571cc2").decode("hex")
        n = "9798683005ff678f507036b44bcbbcfe150115346bf67bd75ad73b42ce6331bf".decode("hex")
        h = crypto.CryptoAlgo(0x800e)
        r = ("d9a268bcc45620cd4602f17e7b1c0b28"
             "671a34f34ffb09c752f822c11464bea3"
             "4d3090ba78ece4703f190d4a0f22cd1b"
             "4cf224685eb317c6617f12368fd5197e").decode("hex")

        self.assertEquals(crypto.CryptSessionKeyXP(m, n, h), r)
        self.assertEquals(crypto.CryptSessionKeyWin7(m, n, h), r)

    def test_CryptSessionKeyWin81Entropy(self):
        m = ("c942b584a88a36f3ce8abe61a62d4036"
             "49dfdd8fd9b256a4a7ff64bfe2b60df8"
             "cb563be71d0d65f8be03ebdd76b4dba1"
             "68a9e3883fee758d2c4aeef040571cc2").decode("hex")
        n = "600ed99a7cba8250b56e6571a852a435ba30522905fc6f297c2f5a31d6b7fa45".decode("hex")
        h = crypto.CryptoAlgo(0x800e)
        e = "5570546f41707000".decode("hex")
        r = ("8fc15ae914a579f22e74547eb4276032"
             "76dee6f2cf72705dd08c473615f2e8e2"
             "3281cee2037aefd5ba0392dc9866a948"
             "feb08a4752c035f2723dd37063be9a13").decode("hex")

        self.assertNotEquals(crypto.CryptSessionKeyXP(m, n, h, e), r)
        self.assertEquals(crypto.CryptSessionKeyWin7(m, n, h, e), r)

    def test_CryptSessionKeyWin81Strong(self):
        m = ("c942b584a88a36f3ce8abe61a62d4036"
             "49dfdd8fd9b256a4a7ff64bfe2b60df8"
             "cb563be71d0d65f8be03ebdd76b4dba1"
             "68a9e3883fee758d2c4aeef040571cc2").decode("hex")
        n = "40da71bec41e2cf971d270977099e1d34030f0875de802967769f7b4906cbc95".decode("hex")
        h = crypto.CryptoAlgo(0x800e)
        s = ("010000003fb376ba974b974e96037865"
             "fb972cec000000000200000000001066"
             "000000010000200000009798683005ff"
             "678f507036b44bcbbcfe150115346bf6"
             "7bd75ad73b42ce6331bf000000000e80"
             "0000000200002000000040da71bec41e"
             "2cf971d270977099e1d34030f0875de8"
             "02967769f7b4906cbc95100000005cce"
             "e1467028df028177bda3c9c34057").decode("hex")
        r = ("45fb9275a0e852ed4b9f2e34ec6100bb"
             "2d3bd5225da37bccb73bfb89b4073dc2"
             "15840c8beeb728201ab69a41945c944c"
             "f6ae645d2e69d00b752ca1552b42ed3d").decode("hex")

        self.assertNotEquals(crypto.CryptSessionKeyXP(m, n, h, None, s), r)
        self.assertEquals(crypto.CryptSessionKeyWin7(m, n, h, None, s), r)

    def test_CryptSessionKeyWin81EntropyStrong(self):
        m = ("c942b584a88a36f3ce8abe61a62d4036"
             "49dfdd8fd9b256a4a7ff64bfe2b60df8"
             "cb563be71d0d65f8be03ebdd76b4dba1"
             "68a9e3883fee758d2c4aeef040571cc2").decode("hex")
        n = "dc2539884092c76194a57bbf090e94dcec850a23f03afcef723de96b6b1a4638".decode("hex")
        h = crypto.CryptoAlgo(0x800e)
        e = "5570546f41707000".decode("hex")
        s = ("010000003fb376ba974b974e96037865"
             "fb972cec000000004400000070007700"
             "64003a00660075006600660061003b00"
             "200065006e00740072006f0070007900"
             "28006100730063006900690029003d00"
             "5500700054006f004100700070000000"
             "106600000001000020000000600ed99a"
             "7cba8250b56e6571a852a435ba305229"
             "05fc6f297c2f5a31d6b7fa4500000000"
             "0e8000000002000020000000dc253988"
             "4092c76194a57bbf090e94dcec850a23"
             "f03afcef723de96b6b1a463810000000"
             "d747986bfd422553f30c8fb1265e1365").decode("hex")
        r = ("3c4236133cc43d416ed650106e0f980d"
             "e4c58e5db4513ea0605207b0835ac69c"
             "2c95f3b5b26511c44543a996b3909526"
             "89843a20dbbaa209e6440b74ff02c49c").decode("hex")

        self.assertNotEquals(crypto.CryptSessionKeyXP(m, n, h, e, s), r)
        self.assertEquals(crypto.CryptSessionKeyWin7(m, n, h, e, s), r)

    def test_CryptDeriveKeyWin8(self):
        h = ("d9a268bcc45620cd4602f17e7b1c0b28"
             "671a34f34ffb09c752f822c11464bea3"
             "4d3090ba78ece4703f190d4a0f22cd1b"
             "4cf224685eb317c6617f12368fd5197e").decode("hex")
        c = crypto.CryptoAlgo(0x6610)
        algo = crypto.CryptoAlgo(0x800e)
        self.assertEquals(crypto.CryptDeriveKey(h, c, algo), h)

    def test_CryptDeriveKeyXP(self):
        h = "9e0ee9a096bcd43c315a211dc7fdb1fd1a01cbec".decode("hex")
        c = crypto.CryptoAlgo(0x6610)
        r = ("e41a0d8b93243370b3722699588a83b2"
             "28b533d82e609a6932bb2f9899be9a4a"
             "f06a5a420963de45").decode("hex")
        algo = crypto.CryptoAlgo(0x8004)

        self.assertEquals(crypto.CryptDeriveKey(h, c, algo), r)

    def test_decrypt_lsa_key_nt5(self):
        lsakey = ("010000000100000000000000060677c4"
                  "63ced8d548dc2c528f2a64a5a4427907"
                  "5941537344cb7231c657f294ee4c5df0"
                  "e57268683de207cba0338cf0ea6b8e51"
                  "54a2ac6b219e2099ece22650").decode("hex")
        syskey = "35bc7242385ed971867e722369bd8db4".decode("hex")
        r = "b150b4b4d14976cb9709fd3c8e001eab".decode("hex")

        keys = crypto.decrypt_lsa_key_nt5(lsakey, syskey)
        self.assertEquals(len(keys), 3)
        self.assertEquals(len(keys[1]), len(r))
        self.assertEquals(keys[1], r)

    def test_decrypt_lsa_key_nt6(self):
        lsakey = ("00000001ecffe17b2a997440aa939adb"
                  "ff26f1fc0300000000000000ee645edd"
                  "3156e5d6c69dc2851f3b59701730733b"
                  "fe63a748a37165aeb4b402b344848e99"
                  "f1442ba42ede3009b35552eb9001e917"
                  "22ac479d752432f239c4412cde0d9f24"
                  "f181cb75bcdc8aab3740f9d1c2153284"
                  "b82651508b4117ea190f4a4bb8fd0100"
                  "88857660ffa44d24e7de12d5bc49105c"
                  "a74e80a204f5272413237ea2ed9aa743"
                  "3743d0674dc4fe828581de36").decode("hex")
        syskey = "9acd05908157e45449e2ee795a9cc87e".decode("hex")
        r = "c6afbd790aa01079860362face32818b155facf4666a0e061b91597c46c9d1a8".decode("hex")

        c, d = crypto.decrypt_lsa_key_nt6(lsakey, syskey)
        self.assertTrue(c in d)
        self.assertEquals(len(d[c]["key"]), len(r))
        self.assertEquals(d[c]["key"], r)

    def test_SystemFunction005(self):
        secret = ("71b13f003a84728dda93ff24240e21fd"
                  "19f93dcccf7c08557e86fa320dc88199"
                  "306732c9f382719a856d4fad4182edd4"
                  "02b88075b64ddf6f").decode("hex")
        key = "b150b4b4d14976cb9709fd3c8e001eab".decode("hex")
        r = ("01 00 00 00 AC F4 A1 4D 92 D2 E2 04 87 BA 8E 6B"
             "69 E0 D2 3C DE 31 98 0B 42 D7 03 64 16 61 20 50"
             "EB C1 E3 77 9C 7F D5 5F 14 A8 92 F4").replace(" ", "").decode("hex")

        self.assertEquals(crypto.SystemFunction005(secret, key), r)

    def test_decrypt_lsa_secret(self):
        secret=("00000001b31b971b40ab9c1ba577d333"
                "685b2f430300000000000000f725e552"
                "7ebd98a928a9e903ddd243a7baa9761b"
                "43237f66ce9a0061652b429269c06e25"
                "d84e8e52195265497843fa95ce3b5472"
                "42c0dea92ab8e7ff0cf266e7e59b7583"
                "3a8a6c92d125cc866198db59e77f66c4"
                "fe1f4f92d276aff94e29a685").decode("hex")
        key = "c6afbd790aa01079860362face32818b155facf4666a0e061b91597c46c9d1a8".decode("hex")
        r = ("01 00 00 00 EB F6 82 84 52 F6 CA 25 BA 36 2F CD"
             "6C 76 36 88 70 70 87 CD 1C 14 65 17 23 BF EB 3A"
             "0E 96 25 31 36 8A DF 95 44 DE D9 78").replace(" ", "").decode("hex")
        d = {"1b971bb3-ab40-1b9c-a577-d333685b2f43": {"key": key}}

        self.assertEquals(crypto.decrypt_lsa_secret(secret, d), r)

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
        self.assertEquals(crypto.derivePwdHash(self.hashpwd, self.sid), self.expected)

    def test_dataDecrypt_aes256_sha512(self):
        r = ("ac23e4d5efcb8979f05fbcb275832a8d"
             "ee9576fbaae76a4de7ead2f313e84bf7"
             "e4be7940b49319463c8cd25a1b4a67c1"
             "5adfbb02e2bbe42c24cd44bec3b9740b"
             "45ebcce3a2ef2788867c28168bf93ea0"
             "48844897f2854df5ac4eb000f72c3a6f"
             "25c65d5347e73c77120cfc3150c87e57"
             "52a017510c1486e71a9d0c32b79f333f"
             "2d0cda0ecc20774cbed8ca071aab9768").decode("hex")
        e = "84e40ab5bab2c5a2965fd185d60cf92fe2c1c9d2".decode("hex")
        iv = "1f63ff38751365ec54748b13d962698e".decode("hex")
        c = ("d23ad4bb1e254c67e2ff2902de8683b3"
             "ca5dc108b821333e2d5059ac6f26db1a"
             "7826abdc93feadcf76aa4db9c0ce32ed"
             "0b261f95f6960a81195231b91a9dd20b"
             "d6a6c5fb8aa6a008b11992d5c191d0b0"
             "63dd99a8e4dc85330db0996aedd2a270"
             "6405201ed74831e084f3b18fc5fdd209"
             "497a2f95c2a4004e54ec731e045d9d38"
             "1861c37760c9d9581662adb67f85255e").decode("hex")

        self.assertEquals(crypto.dataDecrypt(crypto.CryptoAlgo(0x6610), crypto.CryptoAlgo(0x800e), r, e, iv, 5600), c)

    def test_dataDecrypt_3des_sha1(self):
        r = ("95bb351da2ee8c4463c5092a931feba5"
             "613f7bbf1570ecdefd887d5bae9dc18f"
             "a95724c1976c22012fae9cdbf6f70c4a"
             "aab721b9a87e17d725d9dd110f933977"
             "7df1b807c90af31a").decode("hex")
        e = "3fe9c8cffc26443a41ec4a54daf11be86bec0ecb".decode("hex")
        iv = "d43b01cc0590035e567e07b44b6ccead".decode("hex")
        c = ("a2dec8f74d35c7c8de819041309ea0da"
             "720868aa714d72ea94dbb8449b6aec31"
             "58af336a27e482ee14fc79af2de4c98b"
             "fd0d1114168c6d1b54deb513cc7e5bd6"
             "aa7871e9f7b46965").decode("hex")

        self.assertEquals(crypto.dataDecrypt(crypto.CryptoAlgo(0x6603), crypto.CryptoAlgo(0x8009), r, e, iv, 1), c)
        self.assertEquals(crypto.dataDecrypt(crypto.CryptoAlgo(0x6603), crypto.CryptoAlgo(0x8004), r, e, iv, 1), c)

    def test_DPAPIHmac_sha512(self):
        pwdhash = "84e40ab5bab2c5a2965fd185d60cf92fe2c1c9d2".decode("hex")
        hmacSalt = "d23ad4bb1e254c67e2ff2902de8683b3".decode("hex")
        value = ("63dd99a8e4dc85330db0996aedd2a270"
                 "6405201ed74831e084f3b18fc5fdd209"
                 "497a2f95c2a4004e54ec731e045d9d38"
                 "1861c37760c9d9581662adb67f85255e").decode("hex")
        result = ("c5214e216690a6faec7da6e8e04a2d5d"
                  "1dabc1a20796811e7bc6f8146893166c"
                  "1cc9715bf0021c300cf616fa5a763a55"
                  "42a93ac3c58c42c5c54ab94d9186864f").decode("hex")

        self.assertEquals(crypto.DPAPIHmac(crypto.CryptoAlgo(0x800e), pwdhash, hmacSalt, value), result)

    def test_DPAPIHmac_sha1(self):
        pwdhash = "3fe9c8cffc26443a41ec4a54daf11be86bec0ecb".decode("hex")
        hmacSalt = "adc26f78a93e28e2b37bac0b4719011a".decode("hex")
        value = ("ba03b9f6bbdad54015d16009ff29d7be"
                 "d19b821cdb735236feeb4be82b4e8a3d"
                 "211cc28cd79c56f1846afd85fe2c040e"
                 "aa0b997aaec19b88efd945b3303ca1e5").decode("hex")
        result = "8bcd1e26420dca0ffb36d78387bb7ac755591c36".decode("hex")

        self.assertEquals(crypto.DPAPIHmac(crypto.CryptoAlgo(0x8009), pwdhash, hmacSalt, value), result)
        self.assertEquals(crypto.DPAPIHmac(crypto.CryptoAlgo(0x8004), pwdhash, hmacSalt, value), result)


if __name__ == "__main__":
    unittest.main()
