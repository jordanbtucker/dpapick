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
import os
from DPAPI.Core import registry


XP_SECURITY_HIVE = os.path.join(os.path.dirname(__file__), "xp", "SECURITY")
XP_SYSTEM_HIVE = os.path.join(os.path.dirname(__file__), "xp", "SYSTEM")
W7_SECURITY_HIVE = os.path.join(os.path.dirname(__file__), "w7", "SECURITY")
W7_SYSTEM_HIVE = os.path.join(os.path.dirname(__file__), "w7", "SYSTEM")


@unittest.skipUnless(os.path.exists(XP_SYSTEM_HIVE) and os.path.exists(XP_SECURITY_HIVE), "missing registry hives")
class RegeditXPTest(unittest.TestCase):
    def setUp(self):
        self.syskey = "35bc7242385ed971867e722369bd8db4".decode("hex")
        self.lsakey = "b150b4b4d14976cb9709fd3c8e001eab".decode("hex")
        self.expected = ("01000000acf4a14d92d2e20487ba8e6b"
                         "69e0d23cde31980b42d7036416612050"
                         "ebc1e3779c7fd55f14a892f4").decode("hex")

    def test_get_syskey(self):
        r = registry.Regedit()

        self.assertEquals(r.get_syskey(XP_SYSTEM_HIVE), self.syskey)

    def test_get_lsa_key(self):
        r = registry.Regedit()

        self.assertRaises(ValueError, r.get_lsa_key, XP_SECURITY_HIVE)
        r.get_syskey(self.XP_SYSTEM_HIVE)
        self.assertEquals(r.get_lsa_key(XP_SECURITY_HIVE), self.lsakey)

    def test_get_lsa_secrets(self):
        r = registry.Regedit()

        secrets = r.get_lsa_secrets(XP_SECURITY_HIVE, XP_SYSTEM_HIVE)

        self.assertTrue("DPAPI_SYSTEM" in secrets)
        self.assertEquals(secrets["DPAPI_SYSTEM"]["CurrVal"], self.expected)


@unittest.skipUnless(os.path.exists(W7_SYSTEM_HIVE) and os.path.exists(W7_SECURITY_HIVE), "missing registry hives")
class RegeditW7Test(unittest.TestCase):
    def setUp(self):
        self.syskey = "9acd05908157e45449e2ee795a9cc87e".decode("hex")
        self.lsakey = "c6afbd790aa01079860362face32818b155facf4666a0e061b91597c46c9d1a8".decode("hex")
        base = os.path.dirname(__file__)
        self.expected = ("01000000ebf6828452f6ca25ba362fcd"
                         "6c763688707087cd1c14651723bfeb3a"
                         "0e962531368adf9544ded978").decode("hex")

    def test_get_syskey(self):
        r = registry.Regedit()

        self.assertEquals(r.get_syskey(W7_SYSTEM_HIVE), self.syskey)

    def test_get_lsa_key(self):
        r = registry.Regedit()

        self.assertRaises(ValueError, r.get_lsa_key, W7_SECURITY_HIVE)
        r.get_syskey(W7_SYSTEM_HIVE)
        self.assertEquals(r.get_lsa_key(W7_SECURITY_HIVE), self.lsakey)

    def test_get_lsa_secrets(self):
        r = registry.Regedit()

        secrets = r.get_lsa_secrets(W7_SECURITY_HIVE, W7_SYSTEM_HIVE)

        self.assertTrue("DPAPI_SYSTEM" in secrets)
        self.assertEquals(secrets["DPAPI_SYSTEM"]["CurrVal"], self.expected)


if __name__ == "__main__":
    unittest.main()
