#!/usr/bin/env python

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
##  Author: Jean-Michel Picod <jean-michel.picod@cassidian.com>            ##
##                                                                         ##
## This program is distributed under GPLv3 licence (see LICENCE.txt)       ##
##                                                                         ##
#############################################################################

import array, struct, datetime
from DPAPI.probe import DPAPIProbe
from DPAPI.Core import blob

## http://www.securityxploded.com/networkpasswordsecrets.php

class CredentialStore(DPAPIProbe):

    class Credential(DPAPIProbe):
        _entropy = {
                1: "abe2869f-9b47-4cd9-a358-c22904dba7f7\0",
                4: "82BD0E67-9FEA-4748-8672-D5EFE5B779B0\0"
                }
        _type = {
                1: 'Generic',
                2: 'Domain password',
                3: 'Domain certificate',
                4: 'Domain Visible password',
                5: 'Generic certificate',
                6: 'Domain extended'
                }
        _persist = [ "No", "Session", "Local machine", "Entreprise" ]
        def parse(self, data):
            data.eat("2L")
            self.credtype = data.eat("L")
            self.timestamp = data.eat("Q") ##timestamp 64bits
            if self.timestamp > 0:
                self.timestamp /= 10000000
                self.timestamp -= 11644473600

            data.eat("L") ##NULL
            self.persist = data.eat("L")
            data.eat("3L") ##NULL
            self.name = data.eat_length_and_string("L").decode("UTF-16LE")
            self.comment = data.eat_length_and_string("L").decode("UTF-16LE")
            self.alias = data.eat_length_and_string("L").decode("UTF-16LE")
            self.username = data.eat_length_and_string("L").decode("UTF-16LE")
            self.password = None
            if self.credtype == 1 or self.credtype == 4:
                self.dpapiblob = blob.DPAPIBlob(data.eat_length_and_string("L"))
            elif self.credtype == 2: # domain password
                self.password = data.eat_length_and_string("L")
                seld.password = self.password.decode('UTF-16LE')
                self.dpapiblob = None
            elif self.credtype == 3: # domain certificate
                self.password = data.eat_length_and_string("L")
                self.dpapiblob = None

            self.entropy = self._entropy.get(self.credtype)
            if self.entropy != None:
                s = ""
                for c in self.entropy:
                    s += struct.pack("<h", ord(c) << 2)
                self.entropy = s

        def try_decrypt_with_hash(self, h, mkp, sid, **k):
            if self.dpapiblob != None:
                return super(CredentialStore.Credential, self).try_decrypt_with_hash(h, mkp, sid, **k)
            return True

        def postprocess(self, **k):
            if self.credtype == 1:
                v = self.dpapiblob.cleartext.split(":",2)
                self.username = v[0]
                self.password = v[1]
            if self.credtype == 4:
                self.password = self.dpapiblob.cleartext.decode('UTF-16LE')

        def __repr__(self):
            s = [ "Credential" ]
            s.append("    Type    : %s" % self._type.get(self.credtype, "Unknown"))
            s.append("    Persist : %s" % self._persist[self.persist])
            s.append("    Name    : %s" % self.name)
            s.append("    Username: %s" % self.username)
            s.append("    Comment : %s" % self.comment)
            s.append("    Alias   : %s" % self.alias)
            if self.password != None:
                s.append("    Password: %s" % self.password)
            tmp = datetime.datetime.utcfromtimestamp(self.timestamp).ctime()
            s.append("    When    : %s" % tmp)
            if self.entropy != None:
                s.append("    Entropy : %s" % self.entropy.encode('hex'))
            s.append("    Blob    : %s" % repr(self.dpapiblob))
            return "\n".join(s)

    class CredArray(DPAPIProbe):
        def parse(self, data):
            self.revision = data.eat("L")
            self.totallen = data.eat("L")
            self.creds = []
            while data:
                self.creds.append(CredentialStore.Credential(
                    data.eat_string(data.read("L"))))

        def postprocess(self, **k):
            for c in self.creds:
                c.postprocess(**k)

        def try_decrypt_with_hash(self, h, mkp, sid, **k):
            r = True
            for c in self.creds:
                r &= c.try_decrypt_with_hash(h, mkp, sid, **k)
            return r

        def __repr__(self):
            return ("\n" + "-"*50 + "\n").join(map(lambda x: repr(x),
                self.creds))

    def parse(self, data):
        self.dpapiblob = blob.DPAPIBlob(data.remain())
        self.store = None

    def try_decrypt_with_hash(self, h, mkp, sid, **k):
        if super(CredentialStore, self).try_decrypt_with_hash(h, mkp, sid, **k):
            self.store = CredentialStore.CredArray(self.dpapiblob.cleartext)
            return self.store.try_decrypt_with_hash(h, mkp, sid, **k)
        return False

    def __repr__(self):
        s = ["Credential Store"]
        if self.store != None:
            s.append("    %s" % repr(self.store))
        return "\n".join(s)


# vim:ts=4:expandtab:sw=4
