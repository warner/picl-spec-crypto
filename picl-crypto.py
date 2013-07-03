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
def printdec(name, n):
    print_(name+" (base 10):")
    s = str(n)
    while len(s)%32:
        s = " "+s
    for i in range(0, len(s), 32):
        print_(s[i:i+32])

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
    print_("looking for srpSalt that yields an srpVerifier with leading zero")
    makeV = mysrp.create_verifier
    prefix = b"\x00"+b"\xf1"+b"\x00"*14
    #for count in itertools.count():
    for count in [155]:
        # about 500 per second
        if count > 300 and count % 500 == 0:
            print_(count, "tries")
        if count > 1000000:
            raise ValueError("unable to find suitable salt in reasonable time")
        salt = prefix + binascii.unhexlify("%032x"%count)
        (srpVerifier, v_num, x_str, x_num, _) = makeV(emailUTF8, srpPW, salt)
        if srpVerifier[0:1] != b"\x00":
            continue
        print_("found salt on count", count)
        printdec(" x_num", x_num)
        print_(" x", binascii.hexlify(x_str))
        #print_(" v", binascii.hexlify(srpVerifier))
        printdec(" v_num", v_num)
        return salt, srpVerifier, v_num

srpSalt, srpVerifier, v_num = findSalt()

if 1:
    print_("== SRP Verifier")
    printhex("srpSalt", srpSalt)
    printhex("srpVerifier", srpVerifier, groups_per_line=2)

def findB():
    print_("looking for 'b' that yields srpA with leading zero")
    prefix = b"\x00"+b"\xf3"+b"\x00"*(256-2-16)
    s = mysrp.Server(srpVerifier)
    #for count in itertools.count():
    for count in [32]:
        if count > 300 and count % 500 == 0:
            print_(count, "tries")
        if count > 1000000:
            raise ValueError("unable to find suitable value in reasonable time")
        b_str = prefix + binascii.unhexlify("%032x"%count)
        assert len(b_str) == 2048/8, (len(b_str),2048/8)
        b = mysrp.bytes_to_long(b_str)
        B = s.one(b)
        if B[0:1] != b"\x00":
            continue
        print_("found b on count", count)
        printdec(" b_num", b)
        printhex(" b_hex", b_str, groups_per_line=2)
        return b,B

if 1:
    print_("== SRP B")
    b,B = findB()
    printhex("B", B, groups_per_line=2)
    assert mysrp.Server(srpVerifier).one(b) == B

def findA():
    print_("looking for 'a' that yields srpA with leading zero")
    # 'a' is in [1..N-1], so 2048 bits, or 256 bytes
    prefix = b"\x00"+b"\xf2"+b"\x00"*(256-2-16)
    c = mysrp.Client()
    import time
    start = time.time()
    #for count in itertools.count():
    for count in [4444]:
        # this processes about 50 per second. 2^16 needs about 20 minutes.
        if count > 300 and count % 500 == 0:
            now = time.time()
            print_(count, "tries", now - start)
            start = now
        if count > 1000000:
            raise ValueError("unable to find suitable value in reasonable time")
        a_str = prefix + binascii.unhexlify("%032x"%count)
        assert len(a_str) == 2048/8, (len(a_str),2048/8)
        a = mysrp.bytes_to_long(a_str)
        A = c.one(a)
        if A[0:1] != b"\x00":
            continue
        # also require that the computed S has a leading zero
        c.two(B, srpSalt, emailUTF8, srpPW)
        if c._debug_S_bytes[0:1] != b"\x00":
            print_("found good A, but not good S, on count", count)
            continue
        print_("found a on count", count)
        printdec(" a_num", a)
        printhex(" a_hex", a_str, groups_per_line=2)
        return a,A

if 1:
    print_("== SRP A")
    a,A = findA()
    printhex("A", A, groups_per_line=2)
    assert mysrp.Client().one(a) == A


if 1:
    print_("== SRP dance")
    c = mysrp.Client()
    s = mysrp.Server(srpVerifier)
    Ax = c.one(a)
    assert A==Ax
    M1 = c.two(B, srpSalt, emailUTF8, srpPW)
    Bx = s.one(b)
    assert Bx==B
    s.two(A,M1)
    assert c.get_key() == s.get_key()
    printhex("S", c._debug_S_bytes, groups_per_line=2)
    printhex("M1", M1)
    srpK = c.get_key()
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

