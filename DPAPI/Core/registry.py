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

from Registry import Registry
from DPAPI.Core import crypto


class Regedit(object):
    """This class provides several functions to handle registry extraction
    stuff.

    """

    def __init__(self):
        self.syskey = None
        self.lsakey = None
        self.lsa_secrets = {}

    def get_syskey(self, system):
        """Returns the syskey value after decryption from the registry values.

        system argument is the full path to the SYSTEM registry file (usually
        located under %WINDIR%\\system32\\config\\ directory.

        """
        with open(system, 'rb') as f:
            r = Registry.Registry(f)
            cs = r.open("Select").value("Current").value()
            r2 = r.open("ControlSet%03d\\Control\\Lsa" % cs)
            syskey = reduce(
                lambda x, y: x + y,
                map(lambda x: r2.subkey(x)._nkrecord.classname(), ['JD', 'Skew1', 'GBG', 'Data'])
            ).decode("UTF-16LE").decode('hex')

        self.syskey = ''
        transforms = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]
        for i in xrange(len(syskey)):
            self.syskey += syskey[transforms[i]]
        return self.syskey

    def get_lsa_key(self, security):
        """Returns and decrypts the LSA secret key for "CurrentControlSet".
        It is stored under Policy\\PolSecretEncryptionKey.

        security is the full path the the SECURITY registry file (usually
        located under %WINDIR%\\system32\\config\\ directory.

        To decrypt the LSA key, syskey is required. Thus you must first call
        self.get_syskey() if it has not been previously done.

        """
        with open(security, 'rb') as f:
            r = Registry.Registry(f)
            r2 = r.open("Policy\\PolSecretEncryptionKey")
            lsakey = r2.value("(default)").value()
            self.lsakey = crypto.decrypt_lsa_key(lsakey, self.syskey)
        return self.lsakey

    def get_lsa_secrets(self, security, system):
        """Retrieves and decrypts LSA secrets from the registry.
        security and system arguments are the full path to the corresponding
        registry files.
        This function automatically calls self.get_syskey() and
        self.get_lsa_key() functions prior to the secrets retreival.

        Returns a dictionnary of secrets.

        """
        self.get_syskey(system)
        deskey = self.get_lsa_key(security)
        with open(security, 'rb') as f:
            r = Registry.Registry(f)
            r2 = r.open("Policy\\Secrets")
            for i in r2.subkeys():
                val = i.subkey("CurrVal").value('(default)').value()
                self.lsa_secrets[i.name()] = crypto.SystemFunction005(val[0xc:], deskey)
        return self.lsa_secrets

# vim:ts=4:expandtab:sw=4

