# modified version of srp-1.0.2/srp/_pysrp.py (from PyPI):
#  create_salted_verification_key() changed to accept optional salt string
#  (instead of always creating a random one), and to tolerate leading
#  zeros (instead of discarding them)
# uses Python3 to make sure we get the bytes/string issues right


  # N    A large safe prime (N = 2q+1, where q is prime)
  #      All arithmetic is done modulo N.
  # g    A generator modulo N
  # k    Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
  # s    User's salt
  # I    Username
  # p    Cleartext Password
  # H()  One-way hash function
  # ^    (Modular) Exponentiation
  # u    Random scrambling parameter
  # a,b  Secret ephemeral values
  # A,B  Public ephemeral values
  # x    Private key (derived from p and s)
  # v    Password verifier

from hashlib import sha256
import os
import binascii

bytes = type(os.urandom(1))
# 2048
N_str = '''\
AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4\
A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF60\
95179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF\
747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B907\
8717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB37861\
60279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DB\
FBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73'''
assert len(N_str) == 2048/4
N = int(N_str, 16)
g = 2

def bytes_to_long(b):
    return int(binascii.hexlify(b), 16)
def long_to_padded_bytes(l):
    assert len(N_str)%2 == 0, N_str
    s = "%x"%l
    s = "0"*(len(N_str)-len(s)) + s
    return binascii.unhexlify(s)

def gen_x_str(salt, usernameUTF8, passwordUTF8):
    inner = sha256(usernameUTF8+b":"+passwordUTF8).digest()
    outer = sha256(salt+inner).digest()
    return outer

def create_verifier(usernameUTF8, passwordUTF8, salt=None):
    assert isinstance(usernameUTF8, bytes)
    assert isinstance(passwordUTF8, bytes)
    if not salt:
        salt = os.urandom(4)
    assert isinstance(salt, bytes)
    x_str = gen_x_str(salt, usernameUTF8, passwordUTF8)
    x_num = bytes_to_long(x_str)
    print("g", g)
    v_num = pow(g, x_num, N)
    v_str = long_to_padded_bytes(v_num)
    return (v_str, v_num, x_str, x_num, salt)


    
