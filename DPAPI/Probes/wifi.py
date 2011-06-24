#!/usr/bin/env python

#############################################################################
##                                                                         ##
## This file is part of DPAPIck                                            ##
## Windows DPAPI decryption & forensic toolkit                             ##
##                                                                         ##
## Copyright (C) Jean-Michel Picod <jmichel.p@gmail.com>                   ##
## Copyright (C) Elie Bursztein <elie@elie.im>                             ##
##                                                                         ##
## This program is free software; you can redistribute it and/or modify it ##
## under the terms of the GNU General Public License version 2 as          ##
## published by the Free Software Foundation.                              ##
##                                                                         ##
## This program is distributed in the hope that it will be useful, but     ##
## WITHOUT ANY WARRANTY; without even the implied warranty of              ##
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       ##
## General Public License for more details.                                ##
##                                                                         ##
#############################################################################

import string
import hashlib
import datetime
from collections import defaultdict
from DPAPI import *
from DPAPI.eater import Eater,DataStruct

class WirelessInfo(DataStruct):

    class WifiStruct(DataStruct):
        def __init__(self, raw=None):
            self.bssid = None
            self.ssid = None
            DataStruct.__init__(self, raw)

        def __repr__(self):
            s = ["WifiStruct"]
            flags = []
            if self.flags & 0x01:
                flags.append("WEP key present")
            if self.flags & 0x02:
                flags.append("WEP key in hex form")
            if self.flags & 0x04:
                flags.append("volatile")
            if self.flags & 0x08:
                flags.append("enforced by policy")
            if self.flags & 0x10:
                flags.append("802.1x should be enabled")
            s.append("        flags            = %s" % ", ".join(flags))
            s.append("        ssid             = %s" % self.ssid)
            s.append("        privacy          = 0x%x" % self.privacy) ##FIXME add prettyprint
            s.append("        rssi             = %i" % self.rssi)
            s.append("        network type     = 0x%x" % self.nettype) ## FIXME repr
            s.append("        configuration    = %s" % repr(self.configuration)) ##FIXME
            s.append("        infrastructure   = %u" % self.infrastructuremode) ##FIXME
            s.append("        rates            = %s" % repr(self.supportedrates)) ##FIXME repr
            s.append("        key index        = %u" % self.keyindex)
            s.append("        key              = %s" % self.key.encode('hex'))
            s.append("        authentication   = 0x%x" % self.authmode) ##FIXME repr
            s.append("        802.1x           = %r" % (self.ieee8021xEnabled != 0))
            s.append("        eap flags        = 0x%x" % self.eapflags) ## FIXME repr
            eap = "0x%s" % self.eaptype
            if self.eaptype == 0x13:
                eap = "EAP-TLS"
            if self.eaptype == 0x26:
                eap = "PEAP"
            s.append("        eap type         = %s" % eap)
            s.append("        auth data        = %s" % self.authdata)
            s.append("        wpa mcast cipher = 0x%x" % self.wpamcastcipher) ## FIXME repr
            s.append("        media type       = 0x%x" % self.mediatype) ## FIXME repr
            tmp = datetime.datetime.utcfromtimestamp(self.timestamp).ctime()
            s.append("        timestamp        = %s" % tmp)
            return "\n".join(s)

        def parse(self, data):
            self.flags = data.eat("L") ## 1 = WEP key present, 2 = WEP key in hex form, 4 = volatile, 8 = enforced by policy, 0x10 = 802.1x should be enabled
            self.bssid = "%02x:%02x:%02x:%02x:%02x:%02x" % data.eat("6B")
            data.eat("2B") # Reserved
            l = data.eat("L")
            self.ssid = data.eat("32s")
            self.ssid = self.ssid[:l]
            self.privacy = data.eat("L") ## See NDIS_802_11_WEP_STATUS for values
            self.rssi = data.eat("l")
            self.nettype = data.eat("L")
            self.configuration = data.eat("4L")
            self.infrastructuremode = data.eat("L")
            self.supportedrates = data.eat("8B")
            self.keyindex = data.eat("L")
            l = data.eat("L")
            self.key = data.eat("32s")
            self.key = self.key[:l]
            self.authmode = data.eat("L")
            data.eat("2L") ## rdUserData - not used
            self.ieee8021xEnabled = data.eat("L") != 0
            self.eapflags = data.eat("L")
            self.eaptype = data.eat("L") ## 0x13 = EAP-TLS / 0x26 = PEAP
            self.authdata = data.eat_length_and_string("L")
            data.eat("2L") ## rdNetworkData - not used
            self.wpamcastcipher = data.eat("L") ## See NDIS_802_11_WEP_STATUS for values
            self.mediatype = data.eat("L") ## Should always be set to NdisMedium802_3
            data.eat("500B") ## pad
            self.timestamp = (data.eat("Q"))
            if self.timestamp > 0: ## convert from FILETIME to EPOCH
                self.timestamp -= 116444736000000000
                self.timestamp /= 10000000

    def __init__(self, raw=None):
        self.wifiStruct = None
        self.dpapiblob = None
        DataStruct.__init__(self, raw)
        
    def parse(self, data):
        l = data.eat("L") - 4
        self.wifiStruct = WirelessInfo.WifiStruct(data.eat("%us" % l))
        self.dpapiblob = blob.DPAPIBlob(data.remain())

    def __repr__(self):
        s = ["Wirelesskey block"]
        s.append("        BSSID      = %s" % self.bssid)
        s.append("        SSID       = %s" % self.ssid)
        s.append("    %r" % self.wifiStruct)
        s.append("    %r" % self.dpapiblob)
        return "\n".join(s)

    def __getattr__(self, name):
        return getattr(self.wifiStruct, name)

# vim:ts=4:expandtab:sw=4
