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

import hashlib
import hmac
import struct
import array
from M2Crypto import *



def bitcount_B(x):
    x = ((x&0xaa)>>1) + (x&0x55)
    x = ((x&0xcc)>>2) + (x&0x33)
    x = ((x&0xf0)>>4) + (x&0x0f)
    return x

def CryptDeriveKey(h, digest='sha1'):
    _dg = getattr(hashlib, digest)
    if len(h) > 64:
        h = _dg(h).digest()
    h += "\0"*64
    
    ipad = "".join(chr(ord(h[i])^0x36) for i in range(64))
    opad = "".join(chr(ord(h[i])^0x5c) for i in range(64))
    
    tmp = array.array("B")
    tmp.fromstring( _dg(ipad).digest() + _dg(opad).digest() )
    for i,v in enumerate(tmp):
        tmp[i] ^= (bitcount_B(v)^1)&1
    return tmp.tostring()
    
def pbkdf2(passphrase, salt, keylen, iterations, digest='sha1', mac=hmac):
    _dg = getattr(hashlib, digest)
    buff = ""
    i = 0
    while len(buff) < keylen:
        i += 1
        init = mac.new(passphrase, salt + struct.pack("!L", i), _dg).digest()
        U = init
        for j in range(1, iterations):
            U = mac.new(passphrase, init, _dg).digest()
            init = "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(init, U)])
        buff += init
    return buff[:keylen]

_dict = {
    0x6603: { "name": "DES3", "keyLength": 192, "IVLength": 64, "blockLength": 64, "m2": "des_ede3_cbc" },
    0x6609: { "name": "DES2", "keyLength": 128, "IVLength": 64, "blockLength": 64, "m2": "des_ede_cbc" },
    0x6611: { "name": "AES", "keyLength": 128, "IVLength": 128, "blockLength": 128, "m2": "aes_128_cbc" },
    0x660e: { "name": "AES-128", "keyLength": 128, "IVLength": 128, "blockLength": 128, "m2": "aes_128_cbc" },
    0x660f: { "name": "AES-192", "keyLength": 192, "IVLength": 192, "blockLength": 128, "m2": "aes_192_cbc" },
    0x6610: { "name": "AES-256", "keyLength": 256, "IVLength": 256, "blockLength": 128, "m2": "aes_256_cbc" },
    0x6601: { "name": "DES", "keyLength": 64, "IVLength": 64, "blockLength": 64, "m2": "des_cbc" },

    0x8009: { "name": "HMAC", "digestLength": 160, "blockLength": 512 },
    0x8005: { "name": "MAC", "keyLength": 0, "IVLength": 0, "blockLength": 0 },
    0x8001: { "name": "md2", "keyLength": 0, "IVLength": 0, "blockLength": 0 },
    0x8002: { "name": "md4", "keyLength": 0, "IVLength": 0, "blockLength": 0 },
    0x8003: { "name": "md5", "keyLength": 0, "IVLength": 0, "blockLength": 0 },

    0x6602: { "name": "RC2", "keyLength": 0, "IVLength": 0, "blockLength": 0 },
    0x6801: { "name": "RC4", "keyLength": 0, "IVLength": 0, "blockLength": 0 },
    0x660d: { "name": "RC5", "keyLength": 0, "IVLength": 0, "blockLength": 0 },

    0x8004: { "name": "sha1", "digestLength": 160, "blockLength": 512 },
    0x800c: { "name": "sha256", "digestLength": 256, "blockLength": 512 },
    0x800d: { "name": "sha384", "digestLength": 384, "blockLength": 1024 },
    0x800e: { "name": "sha512", "digestLength": 512, "blockLength": 1024 },
    }

class CryptoAlgo:
    def __init__(self, i):
        self._algo = i
        self._dict = _dict

    def value(self):
        return self._algo

    def m2name(self):
        return self._dict[self._algo]["m2"]

    def keyLength(self):
        return self._dict[self._algo]["keyLength"] / 8

    def ivLength(self):
        return self._dict[self._algo]["IVLength"] / 8

    def blockSize(self):
        return self._dict[self._algo]["blockLength"] / 8

    def digestLength(self):
        return self._dict[self._algo]["digestLength"] / 8

    def str(self):
        return "%s" % self
    
    def __str__(self):
        return self._dict[self._algo]["name"]

    def __repr__(self):
        return "%s [%#x]" % (self._dict[self._algo]["name"], self._algo)

def dataDecrypt(raw, password, hmacSalt, cipher, cipherSalt, h, rounds):
    hh = h.str()
    if hh == "HMAC":
        hh = "sha1"
    dg = getattr(hashlib, hh)
    encKey = hmac.new(password, hmacSalt, dg).digest()
    tmp = pbkdf2(encKey, cipherSalt, cipher.keyLength() + cipher.ivLength(),
            rounds, hh)
    cipher = EVP.Cipher(cipher.m2name(),
            tmp[:cipher.keyLength()],
            tmp[cipher.keyLength():],
            m2.decrypt, 0)
    cipher.set_padding(0)
    cleartxt = cipher.update(raw)
    cipher.final()
    return cleartxt

def DpapiHmac(password, hmacSalt, hash, salt2, value):
    hh = hash.str()
    if hh == "HMAC":
        hh = "sha1"
    dg = getattr(hashlib, hh)
    encKey = hmac.new(password, hmacSalt, dg).digest()
    tmpmac = hmac.new(encKey, salt2, dg).digest()
    return hmac.new(tmpmac, value, dg).digest()

# vim:ts=4:expandtab:sw=4
