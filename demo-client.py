
import os, sys, json, base64
import requests
from hashlib import sha256
import hmac
from hkdf import HKDF
import binascii, time
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

#BASEURL = "http://127.0.0.1:9000/"
BASEURL = "https://api-accounts.dev.lcip.org/"
#BASEURL = "https://api-accounts-latest.dev.lcip.org/"

class WebError(Exception):
    def __init__(self, r):
        self.r = r
        self.args = (r, r.content)

def GET(api, versioned="v1/"):
    url = BASEURL+versioned+api
    print "GET", url
    r = requests.get(url)
    if r.status_code != 200:
        raise WebError(r)
    return r.json()

def POST(api, body={}, versioned="v1/"):
    url = BASEURL+versioned+api
    print "POST", url
    r = requests.post(url,
                      headers={"content-type": "application/json"},
                      data=json.dumps(body))
    if r.status_code != 200:
        raise WebError(r)
    return r.json()

from hawk import client as hawk_client

def HAWK_GET(api, id, key, versioned="v1/"):
    url = BASEURL+versioned+api
    print "HAWK_GET", url
    creds = {"id": id.encode("hex"),
             "key": key,
             "algorithm": "sha256"
             }
    header = hawk_client.header(url, "GET", {"credentials": creds,
                                             "ext": ""})
    r = requests.get(url, headers={"authorization": header["field"]})
    if r.status_code != 200:
        raise WebError(r)
    return r.json()

def HAWK_POST(api, id, key, body_object, versioned="v1/"):
    url = BASEURL+versioned+api
    print "HAWK_POST", url
    body = json.dumps(body_object)
    creds = {"id": id.encode("hex"),
             "key": key,
             "algorithm": "sha256"
             }
    header = hawk_client.header(url, "POST",
                                {"credentials": creds,
                                 "ext": "",
                                 "payload": body,
                                 "contentType": "application/json"})
    r = requests.post(url, headers={"authorization": header["field"],
                                    "content-type": "application/json"},
                      data=body)
    if r.status_code != 200:
        raise WebError(r)
    return r.json()

def processAuthToken(authToken):
    x = HKDF(SKM=authToken,
             dkLen=3*32,
             XTS=None,
             CTXinfo=KW("authToken"))
    tokenID, reqHMACkey, requestKey = split(x)
    return tokenID, reqHMACkey, requestKey

def createSession(authToken):
    tokenID, reqHMACkey, requestKey = processAuthToken(authToken)
    x = HKDF(SKM=requestKey,
             dkLen=3*32,
             XTS=None,
             CTXinfo=KW("session/create"))
    respHMACkey = x[:32]
    respXORkey = x[32:]
    r = HAWK_POST("session/create", tokenID, reqHMACkey, {})
    bundle = r["bundle"].decode("hex")
    ct,respMAC = bundle[:-32], bundle[-32:]
    respMAC2 = HMAC(respHMACkey, ct)
    assert respMAC2 == respMAC, (respMAC2.encode("hex"),
                                 respMAC.encode("hex"))
    keyFetchToken, sessionToken = split(xor(ct, respXORkey))
    return str(r["uid"]), keyFetchToken, sessionToken

def processSessionToken(sessionToken):
    x = HKDF(SKM=sessionToken,
             dkLen=3*32,
             XTS=None,
             CTXinfo=KW("sessionToken"))
    tokenID, reqHMACkey, requestKey = split(x)
    return tokenID, reqHMACkey, requestKey

def getEmailStatus(sessionToken):
    tokenID, reqHMACkey, requestKey = processSessionToken(sessionToken)
    return HAWK_GET("recovery_email/status", tokenID, reqHMACkey)

def changePassword(authToken):
    tokenID, reqHMACkey, requestKey = processAuthToken(authToken)
    x = HKDF(SKM=requestKey,
             dkLen=3*32,
             XTS=None,
             CTXinfo=KW("password/change"))
    respHMACkey = x[:32]
    respXORkey = x[32:]
    r = HAWK_POST("password/change/start", tokenID, reqHMACkey, {})
    bundle = r["bundle"].decode("hex")
    ct,respMAC = bundle[:-32], bundle[-32:]
    respMAC2 = HMAC(respHMACkey, ct)
    assert respMAC2 == respMAC, (respMAC2.encode("hex"),
                                 respMAC.encode("hex"))
    keyFetchToken, accountResetToken = split(xor(ct, respXORkey))
    return keyFetchToken, accountResetToken

def getKeys(keyFetchToken, unwrapBKey):
    x = HKDF(SKM=keyFetchToken,
             dkLen=3*32,
             XTS=None,
             CTXinfo=KW("keyFetchToken"))
    tokenID, reqHMACkey, keyRequestKey = split(x)
    y = HKDF(SKM=keyRequestKey,
             dkLen=32+2*32,
             XTS=None,
             CTXinfo=KW("account/keys"))
    respHMACkey = y[:32]
    respXORkey = y[32:]
    r = HAWK_GET("account/keys", tokenID, reqHMACkey)
    bundle = r["bundle"].decode("hex")
    ct,respMAC = bundle[:-32], bundle[-32:]
    respMAC2 = HMAC(respHMACkey, ct)
    assert respMAC2 == respMAC, (respMAC2.encode("hex"),
                                 respMAC.encode("hex"))
    kA, wrapKB = split(xor(ct, respXORkey))
    kB = xor(unwrapBKey, wrapKB)
    return kA, kB

def stretch(emailUTF8, passwordUTF8,
            PBKDF2_rounds_1,
            scrypt_N, scrypt_r, scrypt_p,
            PBKDF2_rounds_2):
    k1 = pbkdf2_bin(passwordUTF8, KWE("first-PBKDF", emailUTF8),
                    PBKDF2_rounds_1, keylen=1*32, hashfunc=sha256)
    time_k1 = time.time()
    printhex("K1", k1)
    k2 = scrypt.hash(k1, KW("scrypt"),
                     N=scrypt_N, r=scrypt_r, p=scrypt_p, buflen=1*32)
    time_k2 = time.time()
    printhex("K2", k2)
    stretchedPW = pbkdf2_bin(k2+passwordUTF8, KWE("second-PBKDF", emailUTF8),
                             PBKDF2_rounds_2, keylen=1*32, hashfunc=sha256)
    printhex("stretchedPW", stretchedPW)
    return stretchedPW

def mainKDF(stretchedPW, mainKDFSalt):
    (srpPW, unwrapBKey) = split(HKDF(SKM=stretchedPW,
                                     XTS=mainKDFSalt,
                                     CTXinfo=KW("mainKDF"),
                                     dkLen=2*32))
    return (srpPW, unwrapBKey)

def signCertificate(sessionToken, pubkey, duration):
    tokenID, reqHMACkey, requestKey = processSessionToken(sessionToken)
    resp = HAWK_POST("certificate/sign", tokenID, reqHMACkey,
                     {"publicKey": pubkey, "duration": duration})
    assert resp["err"] is None
    return str(resp["cert"])

def b64parse(s_ascii):
    s_ascii += "="*((4 - len(s_ascii)%4)%4)
    return base64.urlsafe_b64decode(s_ascii)

def dumpCert(cert):
    pieces = cert.split(".")
    header = json.loads(b64parse(pieces[0]))
    payload = json.loads(b64parse(pieces[1]))
    print "header:", header
    print "payload:", payload
    return header, payload

def destroySession(sessionToken):
    tokenID, reqHMACkey, requestKey = processSessionToken(sessionToken)
    return HAWK_POST("session/destroy", tokenID, reqHMACkey, {})

def processForgotPasswordToken(forgotPasswordToken):
    x = HKDF(SKM=forgotPasswordToken,
             dkLen=2*32,
             XTS=None,
             CTXinfo=KW("forgotPasswordToken")) # XXX: ???
    # not listed in KeyServerProtocol document
    tokenID, reqHMACkey = split(x)
    return tokenID, reqHMACkey

def resendForgotPassword(forgotPasswordToken, emailUTF8):
    tokenID, reqHMACkey = processForgotPasswordToken(forgotPasswordToken)
    return HAWK_POST("password/forgot/resend_code", tokenID, reqHMACkey,
                     {"email": emailUTF8.encode("hex")})

def verifyForgotPassword(forgotPasswordToken, code):
    tokenID, reqHMACkey = processForgotPasswordToken(forgotPasswordToken)
    r = HAWK_POST("password/forgot/verify_code", tokenID, reqHMACkey,
                  {"code": code})
    return r["accountResetToken"]

# https://github.com/mozilla/picl-gherkin/issues/33
MANGLE = False

def main():
    emailUTF8, passwordUTF8, command = sys.argv[1:4]
    assert command in ("create", "login", "changepw", "destroy",
                       "forgotpw1", "forgotpw2", "forgotpw3")
    assert isinstance(emailUTF8, binary_type)
    printhex("email", emailUTF8)
    printhex("password", passwordUTF8)

    GET("__heartbeat__", versioned="")

    if command == "forgotpw1":
        r = POST("password/forgot/send_code",
                 {"email": emailUTF8.encode("hex")})
        print r
        forgotPasswordToken = r["forgotPasswordToken"]
        return

    if command == "forgotpw2":
        forgotPasswordToken = sys.argv[4]
        r = resendForgotPassword(forgotPasswordToken, emailUTF8)
        print r
        return

    if command == "forgotpw3":
        forgotPasswordToken, code, new_passwordUTF8 = sys.argv[4:7]
        accountResetToken = verifyForgotPassword(forgotPasswordToken, code)
        kA,kB = None, None

    if command == "create":
        mainKDFSalt = makeRandom()
        srpSalt = makeRandom()
        PBKDF2_rounds_1 = PBKDF2_rounds_2 = 20*1000
        scrypt_N = 64*1024
        scrypt_r = 8
        scrypt_p = 1
    elif command in ("login", "changepw", "destroy"):
        r = POST("auth/start",
                 {"email": emailUTF8.encode("hex")
                  })
        print "auth/start", r
        st = r["passwordStretching"]
        assert st["type"] == "PBKDF2/scrypt/PBKDF2/v1"
        mainKDFSalt = st["salt"].decode("hex")
        PBKDF2_rounds_1 = st["PBKDF2_rounds_1"]
        PBKDF2_rounds_2 = st["PBKDF2_rounds_2"]
        scrypt_N = st["scrypt_N"]
        scrypt_r = st["scrypt_r"]
        scrypt_p = st["scrypt_p"]

        srpToken = r["srpToken"]
        srpSalt = r["srp"]["salt"].decode("hex")
        B = r["srp"]["B"].decode("hex")
    else:
        assert False

    printhex("mainKDFSalt", mainKDFSalt)
    printhex("srpSalt", srpSalt)

    # MANGLE
    mangled_email = emailUTF8.encode("hex") if MANGLE else emailUTF8
    stretchedPW = stretch(mangled_email, passwordUTF8, PBKDF2_rounds_1,
                          scrypt_N, scrypt_r, scrypt_p, PBKDF2_rounds_2)

    (srpPW, unwrapBKey) = mainKDF(stretchedPW, mainKDFSalt)
    mangled_srpPW = srpPW.encode("hex") if MANGLE else srpPW

    if command == "create":

        (srpVerifier, _, _, _, _) = mysrp.create_verifier(mangled_email,
                                                          mangled_srpPW,
                                                          srpSalt)
        r = POST("account/create",
                 {"email": emailUTF8.encode("hex"),
                  "srp": {
                      "type": "SRP-6a/SHA256/2048/v1",
                      "verifier": srpVerifier.encode("hex"),
                      "salt": srpSalt.encode("hex"),
                    },
                  "passwordStretching": {
                      "type": "PBKDF2/scrypt/PBKDF2/v1",
                      "PBKDF2_rounds_1": PBKDF2_rounds_1,
                      "scrypt_N": scrypt_N,
                      "scrypt_r": scrypt_r,
                      "scrypt_p": scrypt_p,
                      "PBKDF2_rounds_2": PBKDF2_rounds_2,
                      "salt": mainKDFSalt.encode("hex"),
                      },
                  })
        print r
    elif command in ("login", "changepw", "destroy"):
        srpClient = mysrp.Client()
        A = srpClient.one()
        M1 = srpClient.two(B, srpSalt, mangled_email, mangled_srpPW)
        r = POST("auth/finish",
                 {"srpToken": srpToken,
                  "A": A.encode("hex"),
                  "M": M1.encode("hex")})
        print "auth/finish:", r
        bundle = r["bundle"].decode("hex")
        print "bundlelen", len(bundle)

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
    else:
        assert False

    if command == "login":
        uid, keyFetchToken, sessionToken = createSession(authToken)
        printhex("keyFetchToken", keyFetchToken)
        printhex("sessionToken", sessionToken)
        email_status = getEmailStatus(sessionToken)
        print "email status:", email_status
        kA,kB = getKeys(keyFetchToken, unwrapBKey)
        printhex("kA", kA)
        printhex("kB", kB)
        # exercise /certificate/sign . jwcrypto in the server demands that
        # "n" be of a recognized length (512 bits is the shortest it likes)
        pubkey = {"algorithm": "RS",
                  "n": "%d" % (2**512), "e": "2"}
        cert = signCertificate(sessionToken, pubkey, 24*3600*1000)
        print "cert:", cert
        header, payload = dumpCert(cert)
        assert header["alg"] == "RS256"
        # MANGLED
        #assert payload["principal"]["email"] == mangled_email, (payload["principal"]["email"], mangled_email)
        #assert payload["principal"]["email"] == mangled_email.encode("hex")
        assert payload["principal"]["email"] == "%s@api-accounts.dev.lcip.org" % uid
        # exercise /session/destroy
        print "destroying session now"
        print destroySession(sessionToken)
        print "session destroyed, this getEmailStatus should fail:"
        # check that the session is really gone
        try:
            getEmailStatus(sessionToken)
        except WebError as e:
            assert e.r.status_code == 401
            print e.r.content
            print " good, session really destroyed"
        else:
            print "bad, session not destroyed"
            assert 0

    if command == "changepw":
        keyFetchToken, accountResetToken = changePassword(authToken)
        printhex("keyFetchToken", keyFetchToken)
        printhex("accountResetToken", accountResetToken)
        kA,kB = getKeys(keyFetchToken, unwrapBKey)
        printhex("kA", kA)
        printhex("kB", kB)
        new_passwordUTF8 = sys.argv[4]

    if command in ("changepw", "forgotpw3"):
        # stretch new password
        new_stretchedPW = stretch(emailUTF8, new_passwordUTF8, PBKDF2_rounds_1,
                                  scrypt_N, scrypt_r, scrypt_p, PBKDF2_rounds_2)
        new_mainKDFSalt = makeRandom()
        new_srpSalt = makeRandom()
        (new_srpPW, new_unwrapBKey) = mainKDF(new_stretchedPW, new_mainKDFSalt)
        # build new srpVerifier
        (new_srpVerifier, _,_,_,_) = mysrp.create_verifier(emailUTF8,
                                                           new_srpPW,
                                                           new_srpSalt)
        assert len(new_srpVerifier) == 256, len(new_srpVerifier)
        printhex("new_srpVerifier", new_srpVerifier)
        if kB:
            # re-wrap kB
            new_wrap_kB = xor(kB, new_unwrapBKey)
            printhex("new_wrap_kB", new_wrap_kB)
        else:
            new_wrap_kB = "\x00"*len(new_unwrapBKey)

        # submit /account/reset
        x = HKDF(SKM=accountResetToken,
                 XTS=None,
                 CTXinfo=KW("accountResetToken"),
                 dkLen=3*32)
        tokenID, reqHMACkey1, requestKey = split(x)
        plaintext = new_wrap_kB+new_srpVerifier
        print "LEN PLAIN", len(plaintext)
        y = HKDF(SKM=requestKey,
                 XTS=None,
                 CTXinfo=KW("account/reset"),
                 dkLen=32+len(plaintext))
        reqHMACkey2 = y[:32]
        reqXORkey = y[32:]
        bundle = xor(reqXORkey, plaintext)
        bundle_mac = HMAC(reqHMACkey2, bundle)
        payload = {"bundle": (bundle+bundle_mac).encode("hex"),
                   "srp": {
                       "type": "SRP-6a/SHA256/2048/v1",
                       "salt": new_srpSalt.encode("hex"),
                       },
                   "passwordStretching": {
                       "type": "PBKDF2/scrypt/PBKDF2/v1",
                       "PBKDF2_rounds_1": PBKDF2_rounds_1,
                       "scrypt_N": scrypt_N,
                       "scrypt_r": scrypt_r,
                       "scrypt_p": scrypt_p,
                       "PBKDF2_rounds_2": PBKDF2_rounds_2,
                       "salt": new_mainKDFSalt.encode("hex"),
                       },
                   }
        r = HAWK_POST("account/reset", tokenID, reqHMACkey1, payload)
        assert r == {}, r
        print "password changed"

    if command == "destroy":
        tokenID, reqHMACkey, requestKey = processAuthToken(authToken)
        r = HAWK_POST("account/destroy", tokenID, reqHMACkey, {})
        print r

if __name__ == '__main__':
    main()

# exercised:
#  account/create
#  NO: account/devices (might not even be implemented)
#  account/keys
#  account/reset
#  account/destroy
#
#  auth/start
#  auth/finish
#
#  session/create
#  session/destroy

#  recovery_email/status
#  NO: recovery_email/resend_code
#  NO: recovery_email/verify_code
#
#  certificate/sign

#  password/change/start
#  password/forgot/send_code
#  NO: password/forgot/resend_code
#  NO: password/forgot/verify_code

#  NO: get_random_bytes

