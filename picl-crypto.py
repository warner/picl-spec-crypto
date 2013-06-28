# -*- coding: utf-8 -*-

from hashlib import sha256
import hmac
from hkdf import HKDF

def HMAC(key, msg):
    return hmac.new(key, msg, sha256).digest()
def printhex(name, value):
    print "%s:" % name
    for i in range(0, len(value), 8):
        print "".join(["%02x" % ord(c) for c in value[i:i+8]])
    print
def split(value):
    assert len(value)%32 == 0
    return [value[i:i+32] for i in range(0, len(value), 32)]
def KW(name):
    return "identity.mozilla.com/picl/v1/%s" % (name,)

def xor(s1, s2):
    assert len(s1) == len(s2)
    return "".join([chr(ord(s1[i])^ord(s2[i])) for i in range(len(s1))])

def fakeKey(start):
    return "".join([chr(c) for c in range(start, start+32)])

if 0:
    accountToken = "".join([chr(c) for c in range(32)])
    printhex("accountToken", accountToken)
    (tokenID,
     getSignToken, getResetToken) = split(HKDF(SKM=accountToken,
                                               dkLen=3*32,
                                               XTS=None,
                                               CTXinfo=KW("accountToken")))
    printhex("tokenID", tokenID)
    printhex("getSignToken", getSignToken)
    printhex("getResetToken", getResetToken)

if 0:
    print "= SIGN TOKEN"
    (reqHMACkey,
     respHMACkey, respXORkey) = split(HKDF(SKM=getSignToken,
                                           dkLen=3*32,
                                           XTS=None,
                                           CTXinfo=KW("getSignToken")))
    printhex("reqHMACkey", reqHMACkey)
    printhex("respHMACkey", respHMACkey)
    printhex("respXORkey", respXORkey)

if 0:
    print "= RESET TOKEN"
    (reqHMACkey,
     respHMACkey, respXORkey) = split(HKDF(SKM=getResetToken,
                                           dkLen=3*32,
                                           XTS=None,
                                           CTXinfo=KW("getResetToken")))
    printhex("reqHMACkey", reqHMACkey)
    printhex("respHMACkey", respHMACkey)
    printhex("respXORkey", respXORkey)

print "== stretch-KDF"
emailUTF8 = u"andré@example.org".encode("utf-8")
passwordUTF8 = u"pässwörd".encode("utf-8")
printhex("email", emailUTF8)
printhex("password", passwordUTF8)

masterKey = HKDF(SKM=passwordUTF8,
                 XTS=emailUTF8,
                 CTXinfo=KW("fakeStretch"),
                 dkLen=1*32)
printhex("masterKey", masterKey)

if 1:
    print "== main-KDF"
    (unwrapKey, srpPW) = split(HKDF(SKM=masterKey,
                                    XTS=None,
                                    CTXinfo=KW("masterKey"),
                                    dkLen=2*32))
    printhex("unwrapKey", unwrapKey)
    printhex("srpPW", srpPW)

kA = fakeKey(1*32)
wrapkB = fakeKey(2*32)
signToken = fakeKey(3*32)
resetToken = fakeKey(4*32)

if 0:
    print "== getSignToken REQUEST"
    srpK = fakeKey(0)

    x = HKDF(SKM=srpK,
             dkLen=(1+3)*32,
             XTS=None,
             CTXinfo=KW("getSignToken"))
    respHMACkey = x[0:32]
    respXORkey = x[32:]
    printhex("srpK", srpK)
    printhex("respHMACkey", respHMACkey)
    printhex("respXORkey", respXORkey)

    plaintext = kA+wrapkB+signToken
    printhex("plaintext", plaintext)

    ciphertext = xor(plaintext, respXORkey)
    printhex("ciphertext", ciphertext)
    mac = HMAC(respHMACkey, ciphertext)
    printhex("MAC", mac)
    printhex("response", ciphertext+mac)

if 0:
    print "== signCertificate"
    tokenID,reqHMACkey = split(HKDF(SKM=signToken,
                                    XTS=None,
                                    dkLen=2*32,
                                    CTXinfo=KW("signCertificate")))
    printhex("signToken", signToken)
    printhex("tokenID", tokenID)
    printhex("reqHMACkey", reqHMACkey)

if 1:
    print "== resetAccount"
    SRPv = fakeKey(5*32)+fakeKey(6*32)
    plaintext = kA+wrapkB+SRPv
    keys = HKDF(SKM=resetToken,
                XTS=None,
                dkLen=2*32+len(plaintext),
                CTXinfo=KW("resetAccount"))
    tokenID = keys[0:32]
    reqHMACkey = keys[32:64]
    reqXORkey = keys[64:]
    printhex("resetToken", resetToken)
    printhex("tokenID", tokenID)
    printhex("reqHMACkey", reqHMACkey)
    printhex("reqXORkey", reqXORkey)
    printhex("plaintext", plaintext)
    ciphertext = xor(plaintext, reqXORkey)
    printhex("ciphertext", ciphertext)

