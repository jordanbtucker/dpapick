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

import hashlib
import hmac
import struct
import array
from M2Crypto import *



class CryptoAlgo(object):
    """This class is used to wrap Microsoft algorithm IDs with M2Crypto"""
    class _Algo:
        def __init__(self, data):
            self.data=data
        def __getattr__(self, attr):
            if attr in self.data:
                return self.data[attr]
            raise AttributeError(attr)

    _crypto_data = {}
    @classmethod
    def add_algo(cls, algnum, **kargs):
        cls._crypto_data[algnum] = cls._Algo(kargs)
    @classmethod
    def get_algo(cls, algnum):
        return cls._crypto_data[algnum]

    def __init__(self, i):
        self.algnum = i
        self.algo = CryptoAlgo.get_algo(i)

    name = property(lambda self:self.algo.name)
    m2name = property(lambda self:self.algo.m2)
    keyLength = property(lambda self:self.algo.keyLength/8)
    ivLength = property(lambda self: self.algo.IVLength/8)
    blockSize = property(lambda self: self.algo.blockLength/8)
    digestLength = property(lambda self: self.algo.digestLength/8)

    def __repr__(self):
        return "%s [%#x]" % (self.algo.name, self.algnum)


CryptoAlgo.add_algo(0x6603, name="DES3",    keyLength=192, IVLength=64,  blockLength=64,  m2="des_ede3_cbc")
CryptoAlgo.add_algo(0x6609, name="DES2",    keyLength=128, IVLength=64,  blockLength=64,  m2="des_ede_cbc")
CryptoAlgo.add_algo(0x6611, name="AES",     keyLength=128, IVLength=128, blockLength=128, m2="aes_128_cbc")
CryptoAlgo.add_algo(0x660e, name="AES-128", keyLength=128, IVLength=128, blockLength=128, m2="aes_128_cbc")
CryptoAlgo.add_algo(0x660f, name="AES-192", keyLength=192, IVLength=128, blockLength=128, m2="aes_192_cbc")
CryptoAlgo.add_algo(0x6610, name="AES-256", keyLength=256, IVLength=128, blockLength=128, m2="aes_256_cbc")
CryptoAlgo.add_algo(0x6601, name="DES",     keyLength=64,  IVLength=64,  blockLength=64,  m2="des_cbc")

CryptoAlgo.add_algo(0x8009, name="HMAC", digestLength=160, blockLength=512)

CryptoAlgo.add_algo(0x8001, name="md2",  digestLength=128, blockLength=128)
CryptoAlgo.add_algo(0x8002, name="md4",  digestLength=128, blockLength=512)
CryptoAlgo.add_algo(0x8003, name="md5",  digestLength=128, blockLength=512)

CryptoAlgo.add_algo(0x8004, name="sha1",   digestLength=160, blockLength=512)
CryptoAlgo.add_algo(0x800c, name="sha256", digestLength=256, blockLength=512)
CryptoAlgo.add_algo(0x800d, name="sha384", digestLength=384, blockLength=1024)
CryptoAlgo.add_algo(0x800e, name="sha512", digestLength=512, blockLength=1024)




def bitcount_B(x):
    """Internal use. Returns number of 1s in the binary form of the byte x
    Used for the des_set_odd_parity
    """
    x = ((x&0xaa)>>1) + (x&0x55)
    x = ((x&0xcc)>>2) + (x&0x33)
    x = ((x&0xf0)>>4) + (x&0x0f)
    return x


def CryptSessionKey(masterkey, nonce, hashAlgoName='sha1', entropy="", strongPassword=""):
    """Computes the decryption key for DPAPI blob, given the masterkey and
    optionnal information.

    """
    if len(masterkey) > 63:
        dg = hashlib.new(hashAlgoName)
        dg.update(masterkey)
        masterkey = dg.digest()

    masterkey += "\0"*64
    ipad = "".join(chr(ord(masterkey[i])^0x36) for i in range(64))
    opad = "".join(chr(ord(masterkey[i])^0x5c) for i in range(64))

    digest = hashlib.new(hashAlgoName)
    digest.update(ipad)
    digest.update(nonce)
    tmp = digest.digest()

    digest = hashlib.new(hashAlgoName)
    digest.update(opad)
    digest.update(tmp)
    if entropy is not None:
        digest.update(entropy)
    if strongPassword is not None:
        digest.update(strongPassword)
    return digest.digest()

def CryptDeriveKey(h, cipherAlgo, digest='sha1'):
    """Internal use. Mimics the corresponding native Microsoft function"""
    _dg = getattr(hashlib, digest)
    if len(h) > 64:
        h = _dg(h).digest()

    if len(h) >= cipherAlgo.keyLength:
        return h

    h += "\0"*64
    
    ipad = "".join(chr(ord(h[i])^0x36) for i in range(64))
    opad = "".join(chr(ord(h[i])^0x5c) for i in range(64))

    k = _dg(ipad).digest() + _dg(opad).digest()

    if cipherAlgo.name in [ "DES", "DES2", "DES3" ]:
        ## des_set_odd_parity
        tmp = array.array("B")
        tmp.fromstring(k)
        for i,v in enumerate(tmp):
            tmp[i] ^= (bitcount_B(v)^1)&1
        k = tmp.tostring()

    return k

def decrypt_lsa_key(lsakey, syskey):
    """This function decrypts the LSA key using the syskey"""
    dg = hashlib.md5()
    dg.update(syskey)
    for i in xrange(1000):
        dg.update(lsakey[60:76])
    arcfour = RC4.RC4(dg.digest())
    deskey = arcfour.update(lsakey[12:60]) + arcfour.final()
    return deskey[0x10:0x20]

def SystemFunction005(secret, key):
    """This function is used to decrypt LSA secrets.
    Reproduces the corresponding Windows internal function.
    """
    decrypted_data = ''
    j = 0
    for i in range(0, len(secret), 8):
        enc_block = secret[i:i+8]
        block_key = key[j:j+7]
        des_key = array.array('B')
        des_key.append(ord(block_key[0]) >> 1)
        des_key.append(((ord(block_key[0])&0x01)<<6)|(ord(block_key[1])>>2))
        des_key.append(((ord(block_key[1])&0x03)<<5)|(ord(block_key[2])>>3))
        des_key.append(((ord(block_key[2])&0x07)<<4)|(ord(block_key[3])>>4))
        des_key.append(((ord(block_key[3])&0x0F)<<3)|(ord(block_key[4])>>5))
        des_key.append(((ord(block_key[4])&0x1F)<<2)|(ord(block_key[5])>>6))
        des_key.append(((ord(block_key[5])&0x3F)<<1)|(ord(block_key[6])>>7))
        des_key.append(ord(block_key[6])&0x7F)
        for i,v in enumerate(des_key):
            des_key[i] = v << 1
            des_key[i] ^= ((bitcount_B(v) + 1) & 1)
        des_key = des_key.tostring()

        cipher = EVP.Cipher(alg="des_ecb", key=des_key, iv="", op=m2.decrypt)
        cipher.set_padding(0)
        decrypted_data += cipher.update(enc_block) + cipher.final()
        j += 7
        if len(key[j:j+7]) < 7:
            j = len(key[j:j+7])
    dec_data_len = struct.unpack("<L", decrypted_data[:4])[0]
    return decrypted_data[8:8+dec_data_len]

def pbkdf2(passphrase, salt, keylen, iterations, digest='sha1', mac=hmac):
    """Implementation of PBKDF2 that allows specifying both digest and mac
    algorithm.
    Default values:
      * digest = sha1
      * mac = hmac

    Returns the corresponding expanded key which is keylen long.

    """
    _dg = getattr(hashlib, digest)
    buff = ""
    i = 0
    while len(buff) < keylen:
        i += 1
        U = salt + struct.pack("!L", i)
        init = "\0"*len(U)
        for j in xrange(iterations):
            U = mac.new(passphrase, U, _dg).digest()
            init = U = "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(init, U)])
        buff += init
    return buff[:keylen]

def derivePwdHash(pwdhash, userSID, hashAlgo):
    """Internal use. Computes the encryption key from a user's password hash"""
    hname = {"HMAC":"sha1"}.get(hashAlgo.name, hashAlgo.name)
    dg = getattr(hashlib, hname)
    encKey = hmac.new(pwdhash, (userSID+"\0").encode("UTF-16LE"), dg).digest()
    return encKey

def derivePassword(userPwd, userSID, hashAlgo):
    """Internal use. Computes the encryption key from a user's password"""
    return derivePwdHash(hashlib.sha1(userPwd.encode("UTF-16LE")).digest(),
                         userSID, hashAlgo)

def dataDecrypt(cipherAlgo, hashAlgo, raw, encKey, iv, rounds):
    """Internal use. Decrypts data stored in DPAPI structures."""
    hname = {"HMAC":"sha1"}.get(hashAlgo.name, hashAlgo.name)
    derived = pbkdf2(encKey, iv, cipherAlgo.keyLength + cipherAlgo.ivLength,
            rounds, hname)
    key,iv = derived[:cipherAlgo.keyLength],derived[cipherAlgo.keyLength:]
    cipher = EVP.Cipher(cipherAlgo.m2name, key, iv, m2.decrypt, 0)
    cipher.set_padding(0)
    cleartxt = cipher.update(raw) + cipher.final()
    return cleartxt

def DPAPIHmac(hashAlgo, pwdhash, hmacSalt, value):
    """Internal function used to compute HMACs of DPAPI structures"""
    hname = {"HMAC":"sha1"}.get(hashAlgo.name, hashAlgo.name)
    dg = getattr(hashlib, hname)
    encKey = hmac.new(pwdhash, hmacSalt, dg).digest()
    return hmac.new(encKey, value, dg).digest()

# vim:ts=4:expandtab:sw=4
