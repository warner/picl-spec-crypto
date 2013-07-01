# -*- coding: utf-8 -*-

from hashlib import sha256
import hmac
from hkdf import HKDF

def HMAC(key, msg):
    return hmac.new(key, msg, sha256).digest()
def printhex(name, value, groups_per_line=1):
    h = value.encode("hex")
    groups = [h[i:i+16] for i in range(0, len(h), 16)]
    lines = [" ".join(groups[i:i+groups_per_line])
             for i in range(0, len(groups), groups_per_line)]
    print "%s:" % name
    for line in lines:
        print line
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

(unwrapKey, srpPW) = split(HKDF(SKM=masterKey,
                                XTS=None,
                                CTXinfo=KW("masterKey"),
                                dkLen=2*32))

if 0:
    print "== main-KDF"
    printhex("unwrapKey", unwrapKey)
    printhex("srpPW", srpPW)

kA = fakeKey(1*32)
wrapkB = fakeKey(2*32)
signToken = fakeKey(3*32)
resetToken = fakeKey(4*32)

import _pysrp as srp
# _pysrp is based on srp-1.0.2 (from PyPI), but patched to let us pass a
# salt *into* the SRPverifier creation function, instead of creating its
# own random salt.
SRPparms = {"hash_alg": srp.SHA256, "ng_type": srp.NG_2048}

SALT = fakeKey(0*32)
makeV = srp.create_salted_verification_key
(srpSalt, srpVerifier) = makeV(emailUTF8, srpPW,
                               forced_salt=SALT, **SRPparms)
assert srpSalt == SALT

if 1:
    print "== SRP Verifier"
    printhex("srpSalt", srpSalt)
    printhex("srpVerifier", srpVerifier, groups_per_line=2)

if 1:
    print "== SRP dance"
    # note that the python implementation has the client/server interaction
    # hardwired the wrong way around: you must create the Verifier() object
    # with the client's A value, then later extract the server's SRP value.
    # For PiCL, we have the server produce B first, then later the client
    # supplies A.
    force_a = fakeKey(0x03)
    printhex("client internal 'a'", force_a)
    c = srp.User(emailUTF8, srpPW, force_a=force_a, **SRPparms)
    _I,srpA = c.start_authentication()
    assert _I == emailUTF8
    printhex("srpA", srpA, groups_per_line=2)
    force_b = fakeKey(0x04)
    printhex("server internal 'b'", force_b)
    v = srp.Verifier(emailUTF8, srpSalt, srpVerifier, srpA, force_b=force_b,
                     **SRPparms)
    _s,srpB = v.get_challenge()
    assert _s == srpSalt, (_s.encode("hex"), srpSalt.encode("hex"))
    printhex("srpB", srpB, groups_per_line=2)
    srpM1 = c.process_challenge(srpSalt,srpB)
    printhex("srpM1", srpM1)
    # PiCL ignores srpM2, and uses the session key instead
    srpM2 = v.verify_session(srpM1)
    c.verify_session(srpM2)
    assert v.authenticated()
    assert c.authenticated()
    assert c.get_session_key() == v.get_session_key()
    srpK = c.get_session_key()
    printhex("srpK", srpK)

if 0:
    print "== getSignToken REQUEST"
    #srpK = fakeKey(0)

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

if 0:
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

