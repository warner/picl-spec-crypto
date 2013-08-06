
import os, sys, json
import requests
from hashlib import sha256
import hmac
from hkdf import HKDF
import itertools, binascii, time, sys
import six
from six import binary_type, print_, int2byte
import mysrp

# get scrypt-0.6.1 from PyPI, run this with it in your PYTHONPATH
# https://pypi.python.org/pypi/scrypt/0.6.1
import scrypt

# PyPI has four candidates for PBKDF2 functionality. We use "simple-pbkdf2"
# by Armin Ronacher: https://pypi.python.org/pypi/simple-pbkdf2/1.0 . Note
# that v1.0 has a bug which causes segfaults when num_iterations is greater
# than about 88k.
from pbkdf2 import pbkdf2_bin

def makeRandom():
    return os.urandom(32)

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
        print_(s[i:i+32].replace(" ",""))
    print_()

def split(value):
    assert len(value)%32 == 0
    return [value[i:i+32] for i in range(0, len(value), 32)]
def KW(name):
    return b"identity.mozilla.com/picl/v1/" + six.b(name)
def KWE(name, emailUTF8):
    return b"identity.mozilla.com/picl/v1/" + six.b(name) + b":" + emailUTF8

def xor(s1, s2):
    assert isinstance(s1, binary_type), type(s1)
    assert isinstance(s2, binary_type), type(s2)
    assert len(s1) == len(s2)
    return b"".join([int2byte(ord(s1[i:i+1])^ord(s2[i:i+1])) for i in range(len(s1))])

BASEURL = "http://localhost:9000/"

def GET(api):
    r = requests.get(BASEURL+api)
    assert r.status_code == 200, (r, r.content)
    return r.json()

def POST(api, body={}):
    r = requests.post(BASEURL+api,
                      headers={"content-type": "application/json"},
                      data=json.dumps(body))
    assert r.status_code == 200, (r, r.content)
    return r.json()

from hawk import client as hawk_client

def HAWK_GET(api, id, key):
    creds = {"id": id.encode("hex"),
             "key": key.encode("hex"), # TODO: this should not be encoded,
                                       # the server has a bug that needs it
             "algorithm": "sha256"
             }
    header = hawk_client.header(BASEURL+api, "GET", {"credentials": creds,
                                                     "ext": ""})
    r = requests.get(BASEURL+api, headers={"authorization": header["field"]})
    assert r.status_code == 200, (r, r.content)
    return r.json()

def createSession(authToken):
    x = HKDF(SKM=authToken,
             dkLen=5*32,
             XTS=None,
             CTXinfo=KW("session/create"))
    tokenID, reqHMACkey, respHMACkey = split(x[:3*32])
    respXORkey = x[3*32:]
    r = HAWK_POST("session/create", tokenID, reqHMACkey)
    bundle = r["bundle"].decode("hex")
    ct,respMAC = bundle[:-32], bundle[-32:]
    respMAC2 = HMAC(respHMACkey, ct)
    assert respMAC2 == respMAC, (respMAC2.encode("hex"),
                                 respMAC.encode("hex"))
    keyFetchToken, sessionToken = split(xor(ct, respXORkey))
    return keyFetchToken, sessionToken

def getKeys(keyFetchToken, unwrapBKey):
    x = HKDF(SKM=keyFetchToken,
             dkLen=5*32,
             XTS=None,
             CTXinfo=KW("account/keys"))
    tokenID, reqHMACkey, respHMACkey = split(x[:3*32])
    respXORkey = x[3*32:]
    r = HAWK_GET("account/keys", tokenID, reqHMACkey)
    bundle = r["bundle"].decode("hex")
    ct,respMAC = bundle[:-32], bundle[-32:]
    respMAC2 = HMAC(respHMACkey, ct)
    assert respMAC2 == respMAC, (respMAC2.encode("hex"),
                                 respMAC.encode("hex"))
    kA, wrapKB = split(xor(ct, respXORkey))
    kB = xor(unwrapBKey, wrapKB)
    return kA, kB

def main():
    emailUTF8, passwordUTF8, command = sys.argv[1:4]
    assert isinstance(emailUTF8, binary_type)
    printhex("email", emailUTF8)
    printhex("password", passwordUTF8)

    k1 = pbkdf2_bin(passwordUTF8, KWE("first-PBKDF", emailUTF8),
                    20*1000, keylen=1*32, hashfunc=sha256)
    time_k1 = time.time()
    printhex("K1", k1)
    k2 = scrypt.hash(k1, KW("scrypt"), N=64*1024, r=8, p=1, buflen=1*32)
    time_k2 = time.time()
    printhex("K2", k2)
    stretchedPW = pbkdf2_bin(k2+passwordUTF8, KWE("second-PBKDF", emailUTF8),
                             20*1000, keylen=1*32, hashfunc=sha256)
    printhex("stretchedPW", stretchedPW)

    GET("__heartbeat__")

    if command == "create":
        mainKDFSalt = makeRandom()
        srpSalt = makeRandom()
    else:
        r = POST("session/auth/start",
                 {"email": #emailUTF8.encode("hex")
                  emailUTF8.encode("utf-8")
                  })
        print "auth/start", r
        srpToken = r["srpToken"]
        B = r["srp"]["B"].decode("hex")
        srpSalt = r["srp"]["s"].decode("hex")
        mainKDFSalt = r["stretch"]["salt"].decode("hex")
        # ignore stretch.rounds, srp.N_bits, srp.alg

    printhex("mainKDFSalt", mainKDFSalt)
    printhex("srpSalt", srpSalt)

    (srpPW, unwrapBKey) = split(HKDF(SKM=stretchedPW,
                                     XTS=mainKDFSalt,
                                     CTXinfo=KW("mainKDF"),
                                     dkLen=2*32))

    if command == "create":
        (srpVerifier, _, _, _, _) = mysrp.create_verifier(emailUTF8, srpPW,
                                                          srpSalt)

        r = POST("account/create",
                 {#"email": emailUTF8.encode("hex"), # TODO prefer hex
                     "email": emailUTF8.encode("utf-8"),
                  "verifier": srpVerifier.encode("hex"),
                  "salt": srpSalt.encode("hex"),
                  "params": {"srp": {"alg": "sha256", "N_bits": 2048},
                             "stretch": {"salt": mainKDFSalt.encode("hex"),
                                         "rounds": 20000}
                             },
                  })
        print r
    else:
        srpClient = mysrp.Client()
        A = srpClient.one()
        M1 = srpClient.two(B, srpSalt, emailUTF8, srpPW)
        r = POST("session/auth/finish",
                 {"srpToken": srpToken,
                  "A": A.encode("hex"),
                  "M": M1.encode("hex")})
        print "auth/finish:", r
        bundle = r["bundle"].decode("hex")
        print "bundlelen", len(bundle)

        # note: the server is not yet using the new protocol. The old one
        # returns keyFetchToken+sessionToken
        if 1: # old protocol
            x = HKDF(SKM=srpClient.get_key(),
                     dkLen=3*32,
                     XTS=None,
                     CTXinfo=KW("session/auth"))
            respHMACkey = x[0:32]
            respXORkey = x[32:]
            ct,respMAC = bundle[:-32], bundle[-32:]
            respMAC2 = HMAC(respHMACkey, ct)
            printhex("respHMACkey", respHMACkey)
            printhex("respXORkey", respXORkey)
            printhex("ct", ct)
            assert respMAC2 == respMAC, (respMAC2.encode("hex"),
                                         respMAC.encode("hex"))
            keyFetchToken, sessionToken = split(xor(respXORkey,ct))

        if 0: # new protocol
            authToken = getAuthToken(srpClient.get_key())
            x = HKDF(SKM=srpClient.get_key(),
                     dkLen=2*32,
                     XTS=None,
                     CTXinfo=KW("auth/finish"))
            respHMACkey = x[0:32]
            respXORkey = x[32:]
            ct,respMAC = bundle[:-32], bundle[-32:]
            respMAC2 = HMAC(respHMACkey, ct)
            assert respMAC2 == respMAC, (respMAC2.encode("hex"),
                                         respMAC.encode("hex"))
            authToken = xor(ct, respXORkey)
            printhex("authToken", authToken)
            keyFetchToken, sessionToken = createSession(authToken)

        printhex("keyFetchToken", keyFetchToken)
        printhex("sessionToken", sessionToken)

        kA,kB = getKeys(keyFetchToken, unwrapBKey)
        printhex("kA", kA)
        printhex("kB", kB)

if __name__ == '__main__':
    main()

