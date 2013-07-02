# -*- coding: utf-8 -*-
# this should work with both python2.7 and python3.3

from hashlib import sha256
import hmac
from hkdf import HKDF
import itertools, binascii
from six import binary_type, print_, b, int2byte

def HMAC(key, msg):
    return hmac.new(key, msg, sha256).digest()
def printhex(name, value, groups_per_line=1):
    assert isinstance(value, binary_type), type(value)
    h = binascii.hexlify(value).decode("ascii")
    groups = [h[i:i+16] for i in range(0, len(h), 16)]
    lines = [" ".join(groups[i:i+groups_per_line])
             for i in range(0, len(groups), groups_per_line)]
    print_("%s:" % name)
    for line in lines:
        print_(line)
    print_()
def split(value):
    assert len(value)%32 == 0
    return [value[i:i+32] for i in range(0, len(value), 32)]
def KW(name):
    return b"identity.mozilla.com/picl/v1/" + b(name)

def xor(s1, s2):
    assert len(s1) == len(s2)
    return b"".join([int2byte(ord(s1[i])^ord(s2[i])) for i in range(len(s1))])

def fakeKey(start):
    return b"".join([int2byte(c) for c in range(start, start+32)])

print_("== stretch-KDF")
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
    print_("== main-KDF")
    printhex("unwrapKey", unwrapKey)
    printhex("srpPW", srpPW)

kA = fakeKey(1*32)
wrapkB = fakeKey(2*32)
signToken = fakeKey(3*32)
resetToken = fakeKey(4*32)

import mysrp

# choose a salt that gives us a verifier with a leading zero, to ensure we
# exercise padding behavior in implementations of this spec. Otherwise
# padding bugs (dropping a leading zero) would hide in about 255 out of 256
# test runs.
def findSalt():
    makeV = mysrp.create_verifier
    prefix = b"\x00"+b"\x01"+b"\x00"*14
    for count in itertools.count():
        if count > 1000000:
            raise ValueError("unable to find suitable salt in reasonable time")
        print_("===")
        print_(" count", count)
        salt = prefix + binascii.unhexlify("%032x"%count)
        (srpVerifier, v_num, x_str, x_num, _) = makeV(emailUTF8, srpPW, salt)
        print_(" v", binascii.hexlify(srpVerifier))
        print_(repr(srpVerifier[0]))
        if srpVerifier[0:1] != b"\x00":
            continue
        print_(" x", binascii.hexlify(x_str))
        print_(" x_num=", x_num)
        print_(" v_num=", v_num)
        return salt, srpVerifier, v_num

srpSalt, srpVerifier, v_num = findSalt()

if 1:
    print_("== SRP Verifier")
    printhex("srpSalt", srpSalt)
    printhex("srpVerifier", srpVerifier, groups_per_line=2)

if 0:
    print_("== SRP dance")
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
    print_("== getSignToken REQUEST")
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
    print_("== signCertificate")
    tokenID,reqHMACkey = split(HKDF(SKM=signToken,
                                    XTS=None,
                                    dkLen=2*32,
                                    CTXinfo=KW("signCertificate")))
    printhex("signToken", signToken)
    printhex("tokenID", tokenID)
    printhex("reqHMACkey", reqHMACkey)

if 0:
    print_("== resetAccount")
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

