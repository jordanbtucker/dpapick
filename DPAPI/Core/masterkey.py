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

import hashlib
import os
import re
from collections import defaultdict

from DPAPI.Core import eater
from DPAPI.Core import credhist
from DPAPI.Core import crypto


class MasterKey(eater.DataStruct):
    """This class represents a MasterKey block contained in a MasterKeyFile"""

    def __init__(self, raw=None):
        self.decrypted = False
        self.key = None
        self.hmacSalt = None
        self.hmac = None
        self.hmacComputed = None
        eater.DataStruct.__init__(self, raw)

    def parse(self, data):
        self.version = data.eat("L")
        self.iv = data.eat("16s")
        self.rounds = data.eat("L")
        self.hashAlgo = crypto.CryptoAlgo(data.eat("L"))
        self.cipherAlgo = crypto.CryptoAlgo(data.eat("L"))
        self.ciphertext = data.remain()

    def decryptWithHash(self, userSID, pwdhash):
        """Decrypts the masterkey with the given user's hash and SID.
        Simply computes the corresponding key then calls self.decryptWithKey()

        """
        self.decryptWithKey(crypto.derivePwdHash(pwdhash, userSID))

    def decryptWithPassword(self, userSID, pwd):
        """Decrypts the masterkey with the given user's password and SID.
        Simply computes the corresponding key, then calls self.decryptWithKey()

        """
        self.decryptWithKey(crypto.derivePassword(pwd, userSID))

    def decryptWithKey(self, pwdhash):
        """Decrypts the masterkey with the given encryption key. This function
        also extracts the HMAC part of the decrypted stuff and compare it with
        the computed one.

        Note that, once sucessfully decrypted, the masterkey will not be
        decrypted anymore; this function will simply return.

        """
        if self.decrypted:
            return
        ## Compute encryption key
        cleartxt = crypto.dataDecrypt(self.cipherAlgo, self.hashAlgo, self.ciphertext,
                                      pwdhash, self.iv, self.rounds)
        self.key = cleartxt[-64:]
        self.hmacSalt = cleartxt[:16]
        self.hmac = cleartxt[16:16 + self.hashAlgo.digestLength]
        self.hmacComputed = crypto.DPAPIHmac(self.hashAlgo, pwdhash,
                                             self.hmacSalt, self.key)
        self.decrypted = self.hmac == self.hmacComputed

    def __repr__(self):
        s = ["Masterkey block",
             "\tcipher algo  = %s" % repr(self.cipherAlgo),
             "\thash algo    = %s" % repr(self.hashAlgo), "        rounds       = %i" % self.rounds,
             "\tIV           = %s" % self.iv.encode("hex")]
        if self.key is not None:
            s.append("\tkey          = %s" % self.key.encode("hex"))
            s.append("\thmacSalt     = %s" % self.hmacSalt.encode("hex"))
            s.append("\thmac         = %s" % self.hmac.encode("hex"))
            s.append("\thmacComputed = %s" % self.hmacComputed.encode("hex"))
        else:
            s.append("\tciphertext   = %s" % self.ciphertext.encode("hex"))
        return "\n".join(s)


class CredHist(eater.DataStruct):
    """This class represents a Credhist block contained in the MasterKeyFile"""

    def parse(self, data):
        self.magic = data.eat("L")
        self.guid = "%0x-%0x-%0x-%0x%0x-%0x%0x%0x%0x%0x%0x" % data.eat("L2H8B")

    def __repr__(self):
        s = ["CredHist block",
             "\tmagic = %d" % self.magic,
             "\tguid  = %s" % self.guid]
        return "\n".join(s)


class DomainKey(eater.DataStruct):
    """This class represents a DomainKey block contained in the MasterKeyFile.

    Currently does nothing more than parsing. Work on Active Directory stuff is
    still on progress.

    """

    def parse(self, data):
        self.version = data.eat("L")
        self.secretLen = data.eat("L")
        self.accesscheckLen = data.eat("L")
        self.guidKey = "%0x-%0x-%0x-%0x%0x-%0x%0x%0x%0x%0x%0x" % data.eat("L2H8B")  #data.eat("16s")
        self.encryptedSecret = data.eat("%us" % self.secretLen)
        self.accessCheck = data.eat("%us" % self.accesscheckLen)

    def __repr__(self):
        s = ["DomainKey block",
             "\tversion     = %x" % self.version,
             "\tguid        = %s" % self.guidKey,
             "\tsecret      = %s" % self.encryptedSecret.encode("hex"),
             "\taccessCheck = %s" % self.accessCheck.encode("hex")]
        return "\n".join(s)


class MasterKeyFile(eater.DataStruct):
    """This class represents a masterkey file."""

    def __init__(self, raw=None):
        self.masterkey = None
        self.backupkey = None
        self.credhist = None
        self.domainkey = None
        self.decrypted = False
        eater.DataStruct.__init__(self, raw)

    def parse(self, data):
        self.version = data.eat("L")
        data.eat("2L")
        self.guid = data.eat("72s").decode("UTF-16LE").encode("utf-8")
        data.eat("2L")
        self.flags = data.eat("L")
        self.masterkeyLen = data.eat("Q")
        self.backupkeyLen = data.eat("Q")
        self.credhistLen = data.eat("Q")
        self.domainkeyLen = data.eat("Q")

        if self.masterkeyLen > 0:
            self.masterkey = MasterKey()
            self.masterkey.parse(data.eat_sub(self.masterkeyLen))
        if self.backupkeyLen > 0:
            self.backupkey = MasterKey()
            self.backupkey.parse(data.eat_sub(self.backupkeyLen))
        if self.credhistLen > 0:
            self.credhist = CredHist()
            self.credhist.parse(data.eat_sub(self.credhistLen))
        if self.domainkeyLen > 0:
            self.domainkey = DomainKey()
            self.domainkey.parse(data.eat_sub(self.domainkeyLen))

    def decryptWithHash(self, userSID, h):
        """See MasterKey.decryptWithHash()"""
        if not self.masterkey.decrypted:
            self.masterkey.decryptWithHash(userSID, h)
        if not self.backupkey.decrypted:
            self.backupkey.decryptWithHash(userSID, h)
        self.decrypted = self.masterkey.decrypted or self.backupkey.decrypted

    def decryptWithPassword(self, userSID, pwd):
        """See MasterKey.decryptWithPassword()"""
        self.decryptWithHash(userSID, hashlib.sha1(pwd.encode('UTF-16LE')).digest())

    def decryptWithKey(self, pwdhash):
        """See MasterKey.decryptWithKey()"""
        if not self.masterkey.decrypted:
            self.masterkey.decryptWithKey(pwdhash)
        if not self.backupkey.decrypted:
            self.backupkey.decryptWithKey(pwdhash)
        self.decrypted = self.masterkey.decrypted or self.backupkey.decrypted

    def get_key(self):
        """Returns the first decrypted block between Masterkey and BackupKey.
        If none has been decrypted, returns the Masterkey block.

        """
        if self.masterkey.decrypted:
            return self.masterkey.key
        elif self.backupkey.decrypted:
            return self.backupkey.key
        return self.masterkey.key


    def __repr__(self):
        s = ["\n#### MasterKeyFile %s ####" % self.guid,
             "\tversion   = %#d" % self.version,
             "\tFlags     = %#x" % self.flags,
             "\tMasterKey = %d" % self.masterkeyLen,
             "\tBackupKey = %d" % self.backupkeyLen,
             "\tCredHist  = %d" % self.credhistLen,
             "\tDomainKey = %d" % self.domainkeyLen]
        if self.masterkey:
            s.append("    + Master Key: %s" % repr(self.masterkey))
        if self.backupkey:
            s.append("    + Backup Key: %s" % repr(self.backupkey))
        if self.credhist:
            s.append("    + %s" % repr(self.credhist))
        if self.domainkey:
            s.append("    + %s" % repr(self.domainkey))
        return "\n".join(s)


class MasterKeyPool(object):
    """This class is the pivot for using DPAPIck. It manages all the DPAPI
    structures and contains all the decryption intelligence.

    """

    def __init__(self):
        self.keys = defaultdict(lambda: [])
        self.creds = { }
        self.system = None
        self.passwords = []

    def addMasterKey(self, mkey):
        """Add a MasterKeyFile is the pool.

        mkey is a string representing the content of the file to add.

        """
        mkf = MasterKeyFile(mkey)
        self.keys[mkf.guid].append(mkf)

    def getMasterKeys(self, guid):
        """Returns an array of Masterkeys corresponding the the given GUID.

        guid is a string.

        """
        return self.keys.get(guid, [])

    def addSystemCredential(self, blob):
        """Adds DPAPI_SYSTEM token to the pool.

        blob is a string representing the LSA secret token

        """
        self.system = credhist.CredSystem(blob)

    def addCredhist(self, sid, cred):
        """Internal use. Adds a CredHistFile to the pool.

        sid is a string representing the user's SID
        cred is CredHistFile object.

        """
        self.creds[sid] = cred

    def addCredhistFile(self, sid, credfile):
        """Adds a Credhist file to the pool.

        sid is a string representing the user's SID
        credfile is the full path to the CREDHIST file to add.

        """
        f = open(credfile, 'rb')
        self.addCredhist(sid, credhist.CredHistFile(f.read()))
        f.close()

    def loadDirectory(self, directory):
        """Adds every masterkey contained in the given directory to the pool.
        If a file is not a valid Masterkey file, this function simply goes to
        the next file without complaining.

        directory is a string representing the directory path to add.

        """
        for k in os.listdir(directory):
            if re.match("^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$", k, re.IGNORECASE):
                try:
                    f = open(os.path.join(directory, k), 'rb')
                    self.addMasterKey(f.read())
                    f.close()
                except:
                    pass

    def try_credential(self, userSID, password):
        """This function tries to decrypt every masterkey contained in the pool
        that has not been successfully decrypted yet with the given password and
        SID.

        userSID is a string representing the user's SID
        password is a string representing the user's password.

        Returns the number of masterkey that has been successfully decrypted
        with those credentials.

        """
        n = 0
        for mk in self.keys.values():
            if not mk.decrypted:
                mk.decryptWithPassword(userSID, password)
                if mk.decrypted:
                    self.passwords.append(password)
                    n += 1
        return n

    def __repr__(self):
        s = ["MasterKeyPool:",
             "Passwords:",
             repr(self.passwords),
             "Keys:",
             repr(self.keys.items()),
             repr(self.system),
             "CredHist entries:"]
        for i in self.creds.keys():
            s.append("\tSID: %s" % i)
            s.append(repr(self.creds[i]))
        return "\n".join(s)

# vim:ts=4:expandtab:sw=4
