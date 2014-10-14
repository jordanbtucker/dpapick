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
from DPAPI.Core import credhist
import struct


class RPC_SIDTest(unittest.TestCase):
    def test_parse(self):
        self.assertRaises(struct.error, credhist.RPC_SID, "")
        r = credhist.RPC_SID("\x00" * 10)
        self.assertEquals(r.version, 0)
        self.assertEquals(r.idAuth, 0)
        self.assertEquals(len(r.subAuth), 0)

    def test_string(self):
        r = credhist.RPC_SID("\x00" * 10)
        self.assertEquals(str(r), "S-0-0")
        r = credhist.RPC_SID("01050123456789AB010000000200000003000000040000000500000006000000".decode("hex"))
        self.assertEquals(r.version, 1)
        self.assertEquals(r.idAuth, 0x0123456789AB)
        self.assertEquals(len(r.subAuth), 5)
        for i in range(5):
            self.assertEquals(r.subAuth[i], i + 1)


class CredSystemTest(unittest.TestCase):
    def test_parse(self):
        self.assertRaises(struct.error, credhist.CredSystem, "")
        c = credhist.CredSystem("\x01\x00\x00\x00" + "a" * 20 + "b" * 20)
        self.assertEquals(c.revision, 1)
        self.assertEquals(c.machine, "a" * 20)
        self.assertEquals(c.user, "b" * 20)


class CredhistEntryTest(unittest.TestCase):
    def test_parse(self):
        pass


class CredHistFileTest(unittest.TestCase):
    def setUp(self):
        self.credhist = ("01000000b7335635e31e464a8e93c099"
                         "8e062938000000000100000009800000"
                         "a00f00001c0000000366000014000000"
                         "140000004d92b9fdaa9a3c5958e48419"
                         "6af73915010500000000000515000000"
                         "b4b7cd222ad0375c828ba628e9030000"
                         "05c0bb13340ca2a1ed81e931fb9f912d"
                         "a99babb67db24d3e2ac491118cdb9051"
                         "c9cdf1c510b4032501000000fb281ef0"
                         "b217d74f81d60c005e91e87288000000"
                         "0100000009800000a00f00001c000000"
                         "036600001400000014000000c0878ea6"
                         "7d84a3d9d53a72d26e53594b01050000"
                         "0000000515000000b4b7cd222ad0375c"
                         "828ba628e9030000c2451074d71c886f"
                         "534dd152e07142ddf5b488ca304458b1"
                         "eabf634fed22a3aa5afebe210f915e21"
                         "0100000067c385547d44dc4984c9553e"
                         "4e005d58880000000100000009800000"
                         "a00f00001c0000000366000014000000"
                         "14000000453685f445507b7cbc3d6f7b"
                         "c7a942a8010500000000000515000000"
                         "b4b7cd222ad0375c828ba628e9030000"
                         "6b0ddd8b8dbba505f40b161609f28835"
                         "bb38c1f868f859da01c1cb20213e5a17"
                         "ea52b3d72d7b2c9b01000000fb619070"
                         "4e2f4f4f981ed47aa25dd05488000000"
                         "0100000009800000a00f00001c000000"
                         "0366000014000000140000000d15c14e"
                         "4c712f424a0fc0a1c70bd10501050000"
                         "0000000515000000b4b7cd222ad0375c"
                         "828ba628e90300008ecc9115fd57c333"
                         "ee87eb7fd6b02988f65624f16a77733d"
                         "7e9c7b43992671cd4a8bb50151ed3657"
                         "010000008c0cc86717255245ba9544f8"
                         "8914bc1388000000".decode("hex"))

    def test_parse(self):
        c = credhist.CredHistFile(self.credhist)
        self.assertEquals(c.curr_guid, "355633b7-1ee3-4a46-8e93-c0998e62938")
        self.assertEquals(len(c.entries.items()), 4)
        g, i = c.entries.items()[0]
        self.assertEquals(i.revision, 1)
        self.assertEquals(i.hashAlgo.algnum, 0x8009)
        self.assertEquals(i.rounds, 4000)
        self.assertEquals(i.cipherAlgo.algnum, 0x6603)
        self.assertEquals(i.shaHashLen, 20)
        self.assertEquals(i.ntHashLen, 20)
        self.assertEquals(str(i.userSID), "S-1-5-21-583907252-1547161642-682003330-1001")
        self.assertEquals(i.guid, g)
        self.assertEquals(len(i.iv), 16)
        self.assertEquals(i.iv, "453685f445507b7cbc3d6f7bc7a942a8".decode("hex"))



if __name__ == "__main__":
    unittest.main()
