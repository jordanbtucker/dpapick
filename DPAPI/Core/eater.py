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
## This program is distributed under dual cumulative licences:             ##
##    * GPLv3 for non-commercial use of this program (see LICENCE.GPLv3)   ##
##    * EADS licence for commercial use (see LICENCE.EADS)                 ##
##                                                                         ##
## If you want to make a commercial tool using this program, contact the   ##
## author for information and a quotation                                  ##
##                                                                         ##
#############################################################################

import struct

class Eater:
    def __init__(self, raw, offset=0, end=None, endianness="<"):
        self.raw = raw
        self.ofs = offset
        if end is None:
            end = len(raw)
        self.end = end
        self.endianness = endianness
    def prepare_fmt(self, fmt):
        if fmt[0] not in ["<",">","!","@"]:
            fmt = self.endianness+fmt
        return fmt, struct.calcsize(fmt)

    def eat(self, fmt):
        fmt,sz = self.prepare_fmt(fmt)
        v = struct.unpack_from(fmt, self.raw, self.ofs)
        if len(v) == 1:
            v = v[0]
        self.ofs += sz
        return v
    def eat_string(self, length):
        return self.eat("%us" % length)
    def eat_length_and_string(self, fmt):
        l = self.eat(fmt)
        return self.eat_string(l)

    def pop(self, fmt):
        fmt,sz = self.prepare_fmt(fmt)
        self.end -= sz
        v = struct.unpack_from(fmt, self.raw, self.end)
        if len(v) == 1:
            v = v[0]
        return v
    def pop_string(self, length):
        return self.pop("%us" % length)
    def pop_length_and_string(self, fmt):
        l = self.pop(fmt)
        return self.pop_string(l)
    
    def remain(self):
        return self.raw[self.ofs:]
    def eat_sub(self, length):
        sub= self.__class__(self.raw[self.ofs:self.ofs+length], 
                            endianness = self.endianness)
        self.ofs += length
        return sub
    def __nonzero__(self):
        return self.ofs < self.end

class DataStruct:
    def __init__(self, raw=None):
        if raw is not None:
            self.parse( Eater(raw, endianness="<") )
