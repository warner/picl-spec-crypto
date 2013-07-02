# -*- coding: utf-8 -*-

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
import six

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

# SRP-6a defines 'k' to be H(N+g) (both padded, result as an int). SRP-6
# merely sets k=3
k_bytes = sha256(long_to_padded_bytes(N)+long_to_padded_bytes(g)).digest()
k = bytes_to_long(k_bytes)

def gen_x_bytes(salt, usernameUTF8, passwordUTF8):
    inner = sha256(usernameUTF8+b":"+passwordUTF8).digest()
    outer = sha256(salt+inner).digest()
    return outer

def create_verifier(usernameUTF8, passwordUTF8, salt=None):
    assert isinstance(usernameUTF8, bytes)
    assert isinstance(passwordUTF8, bytes)
    if not salt:
        salt = os.urandom(4)
    assert isinstance(salt, bytes)
    x_bytes = gen_x_bytes(salt, usernameUTF8, passwordUTF8)
    x = bytes_to_long(x_bytes)
    v = pow(g, x, N)
    v_str = long_to_padded_bytes(v)
    return (v_str, v, x_bytes, x, salt)

class Client:
    def __init__(self):
        pass
    def one(self, a=None):
        if not a:
            a = bytes_to_long(os.urandom(32)) # TODO: why 32?
        assert isinstance(a, six.integer_types)
        self.a = a
        A = pow(g, self.a, N)
        self.A_bytes = long_to_padded_bytes(A)
        assert isinstance(self.A_bytes, six.binary_type)
        return self.A_bytes

    def two(self, B_bytes, salt, usernameUTF8, passwordUTF8):
        assert self.A_bytes, "must call Client.one() before Client.two()"
        assert isinstance(B_bytes, six.binary_type)
        B = bytes_to_long(B_bytes)
        if B % N == 0:
            raise ValueError("SRP-6a safety check failed: B is zero-ish")
        u_bytes = sha256(self.A_bytes+B_bytes).digest()
        u = bytes_to_long(u_bytes)
        if u == 0:
            raise ValueError("SRP-6a safety check failed: u is zero")
        x_bytes = gen_x_bytes(salt, usernameUTF8, passwordUTF8)
        x = bytes_to_long(x_bytes)
        v = pow(g, x, N)
        S = pow((B - k*v) % N,   (self.a + u*x),   N)
        S_bytes = long_to_padded_bytes(S)
        self.K = sha256(S_bytes).digest()
        M1_bytes = sha256(self.A_bytes + B_bytes + S_bytes).digest()
        self.expected_M2 = sha256(self.A_bytes + M1_bytes + S_bytes).digest()
        return M1_bytes

    def three(self, M2_bytes):
        if M2_bytes != self.expected_M2:
            raise ValueError("SRP error: received M2 does not match, server does not know our Verifier")

    def get_key(self):
        return self.K

class Server:
    def __init__(self, verifier):
        assert isinstance(verifier, six.binary_type)
        self.v = bytes_to_long(verifier)

    def one(self, b=None):
        if not b:
            b = bytes_to_long(os.urandom(32)) # TODO: why 32?
        assert isinstance(b, six.integer_types)
        self.b = b

        B = (k*self.v + pow(g, self.b, N)) % N
        self.B_bytes = long_to_padded_bytes(B)
        assert isinstance(self.B_bytes, six.binary_type)
        return self.B_bytes

    def two(self, A_bytes, M1_bytes):
        A = bytes_to_long(A_bytes)
        if A % N == 0:
            raise ValueError("SRP-6a safety check failed: A is zero-ish")
        u_bytes = sha256(A_bytes+self.B_bytes).digest()
        u = bytes_to_long(u_bytes)
        if u == 0:
            raise ValueError("SRP-6a safety check failed: u is zero")
        S = pow((A * pow(self.v, u, N)) % N, self.b, N)
        S_bytes = long_to_padded_bytes(S)
        expected_M1_bytes = sha256(A_bytes + self.B_bytes + S_bytes).digest()
        if M1_bytes != expected_M1_bytes:
            raise ValueError("SRP error: received M1 does not match, client does not know password")
        # they know the password! yay!
        self.K = sha256(S_bytes).digest()
        M2 = sha256(A_bytes + M1_bytes + S_bytes).digest()
        return M2 # client can optionally check this to test us

    def get_key(self):
        return self.K

def test():
    emailUTF8 = u"andré@example.org".encode("utf-8")
    passwordUTF8 = u"pässwörd".encode("utf-8")
    v,_,_,_,salt = create_verifier(emailUTF8, passwordUTF8)

    s = Server(v)
    B = s.one()

    c = Client()
    A = c.one()

    M1 = c.two(B, salt, emailUTF8, passwordUTF8)

    M2 = s.two(A, M1)

    c.three(M2)

    assert c.get_key() == s.get_key()
    six.print_("test passed")

if __name__ == '__main__':
    test()

# pysrp server makes M=H( (H(N)^H(g)) +H(I)+salt+A+B+K)
# H_AMK = H(A+M+K)
# client.process_challenge returns M
# server.verify_session compares M, returns H_AMK
# client.verify_session compares H_AMK
#
# so M/H_AMK are taking the role of M1/M2 in my code and the SRP6 paper. My
# M1=H(A+B+S), so they're just being more thorough. Using K instead of S is
# slightly safer, including I and the salt prevents a sort of mixed-message
# attack. Why use HNxorHg instead of just including N and g?
#
# RFC2945 (the SRP3 one) does XORt. It also has a weird SHA_Interleave()
# function to get from S to K.
#
# The SRP3 paper uses M1=H(A+B+K) and M2=H(A+M1+K). The SRP6 paper claims
# that the SRP3 paper used M1=H(A+B+S) and M2=H(A+M1+S). Neither use XOR.
# The wikipedia artcle uses XOR (as "one possible way").
