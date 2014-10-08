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
from DPAPI.Core import registry


class RegeditXPTest(unittest.TestCase):
    def setUp(self):
        self.syskey = "35bc7242385ed971867e722369bd8db4".decode("hex")
        self.lsakey = "b150b4b4d14976cb9709fd3c8e001eab".decode("hex")
        # FIXME: Create temp files and fill them with data
        self.fake_security_hive = None
        self.fake_system_hive = None
        # FIXME: set the expected value for DPAPI_SYSTEM token
        self.expected = "".decode("hex")

    def test_get_syskey(self):
        r = registry.Regedit()

        self.assertEquals(r.get_syskey(), self.syskey)

    def test_get_lsa_key(self):
        r = registry.Regedit()

        self.assertEquals(r.get_lsa_key(), self.lsakey)

    def test_get_lsa_secrets(self):
        r = registry.Regedit()
        secrets = r.get_lsa_secrets(self.fake_security_hive, self.fake_system_hive)

        self.assertEquals(len(secrets), 1)
        self.assertTrue("DPAPI_SYSTEM" in secrets)
        self.assertEquals(secrets["DPAPI_SYSTEM"], self.expected)

if __name__ == "__main__":
    unittest.main()
