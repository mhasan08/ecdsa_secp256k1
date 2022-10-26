
'''
    Created by
        Hasan, Munawar
'''



import pickle
from collections import namedtuple
from hashlib import sha256
from math import ceil, log
import sys
from typing import NamedTuple, final
import argparse
import math
import os

#Bitcoin ECDSA Parameters
#https://en.bitcoin.it/wiki/Secp256k1
class Secp256k1Params:
    def __init__(self):
        self.p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        self.a = 0x00
        self.b = 0x07
        self.Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        self.Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
        self.n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        self.h = 0x01

    def get_secp256k1params(self):
        return dict(
            p=self.p,
            a=self.a,
            b=self.b,
            Gx=self.Gx,
            Gy=self.Gy,
            n=self.n,
            h=self.h
        )

DEBUG=False

class debugcls(object):
    @final
    @staticmethod
    def testvector():
        tv = [
            {
                'pk': 0xD30519BCAE8D180DBFCC94FE0B8383DC310185B0BE97B4365083EBCECCD75759,
                'pubk_x': 0x3AF1E1EFA4D1E1AD5CB9E3967E98E901DAFCD37C44CF0BFB6C216997F5EE51DF,
                'pubk_y': 0xE4ACAC3E6F139E0C7DB2BD736824F51392BDA176965A1C59EB9C3C5FF9E85D7A,
                'k': 0xDC87789C4C1A09C97FF4DE72C0D0351F261F10A2B9009C80AEE70DDEC77201A0,
                'msg_hash': 0x3F891FDA3704F0368DAB65FA81EBE616F4AA2A0854995DA4DC0B59D2CADBD64F,
                'r': 0xA5C7B7756D34D8AAF6AA68F0B71644F0BEF90D8BFD126CE951B6060498345089,
                's': 0xBC9644F1625AF13841E589FD00653AE8C763309184EA0DE481E8F06709E5D1CB,
                'is_ok': True
            },
            {
                'pk': 0xEBB2C082FD7727890A28AC82F6BDF97BAD8DE9F5D7C9028692DE1A255CAD3E0F,
                'pubk_x': 0x779DD197A5DF977ED2CF6CB31D82D43328B790DC6B3B7D4437A427BD5847DFCD,
                'pubk_y': 0xE94B724A555B6D017BB7607C3E3281DAF5B1699D6EF4124975C9237B917D426F,
                'k': 0x49A0D7B786EC9CDE0D0721D72804BEFD06571C974B191EFB42ECF322BA9DDD9A,
                'msg_hash': 0x4B688DF40BCEDBE641DDB16FF0A1842D9C67EA1C3BF63F3E0471BAA664531D1A,
                'r': 0x241097EFBF8B63BF145C8961DBDF10C310EFBB3B2676BBC0F8B08505C9E2F795,
                's': 0x21006B7838609339E8B415A7F9ACB1B661828131AEF1ECBC7955DFB01F3CA0E,
                'is_ok': True
            },
            {
                'pk': 0xFEE0A1F7AFEBF9D2A5A80C0C98A31C709681CCE195CBCD06342B517970C0BE1E,
                'pubk_x': 0xAC242D242D23BE966085A2B2B893D989F824E06C9AD0395A8A52F055BA39ABB2,
                'pubk_y': 0x4836AB292C105A711ED10FCFD30999C31FF7C02456147747E03E739AD527C380,
                'k': 0x49A0D7B786EC9CDE0D0721D72804BEFD06571C974B191EFB42ECF322BA9DDD9A,
                'msg_hash': 0x4B688DF40BCEDBE641DDB16FF0A1842D9C67EA1C3BF63F3E0471BAA664531D1A,
                'r': 0x241097EFBF8B63BF145C8961DBDF10C310EFBB3B2676BBC0F8B08505C9E2F795,
                's': 0x6E17513B1E8849593B5EE748C86C7E2E8FEB9B83DEE70FCEF29E843E3FE363FB,
                'is_ok': True
            }
        ]
        return tv

class FP(NamedTuple):
    p: int
    a: int
    b: int

#https://rosettacode.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
#overload operators for EC basic op
class ECOps(NamedTuple):
    curve: FP
    x: int
    y: int

    @classmethod
    def build(cls, curve, x, y):
        x = x % curve.p
        y = y % curve.p
        rv = cls(curve, x, y)
        if not rv.is_identity():
            assert rv.in_curve()
        return rv

    def get_identity(self):
        return ECOps.build(self.curve, 0, 0)

    def copy(self):
        return ECOps.build(self.curve, self.x, self.y)

    def __neg__(self):
        return ECOps.build(self.curve, self.x, -self.y)

    def __sub__(self, Q):
        return self + (-Q)

    def __equals__(self, Q):
        return self.x == Q.x and self.y == Q.y

    def is_identity(self):
        return self.x == 0 and self.y == 0

    def __add__(self, Q):
        p = self.curve.p
        if self.is_identity():
            return Q.copy()
        if Q.is_identity():
            return self.copy()
        if Q.x == self.x and (Q.y == (-self.y % p)):
            return self.get_identity()

        if self != Q:
            l = ((Q.y - self.y) * modinv(Q.x - self.x, p)) % p
        else:
            l = ((3 * self.x ** 2 + self.curve.a) * modinv(2 * self.y, p)) % p
        l = int(l)

        Rx = (l ** 2 - self.x - Q.x) % p
        Ry = (l * (self.x - Rx) - self.y) % p
        return ECOps.build(self.curve, Rx, Ry)

    def in_curve(self):
        return ((self.y ** 2) % self.curve.p) == (
            (self.x ** 3 + self.curve.a * self.x + self.curve.b) % self.curve.p
        )

    def __mul__(self, s):
        r0 = self.get_identity()
        r1 = self.copy()
        
        for i in range(ceil(log(s + 1, 2)) - 1, -1, -1):
            if ((s & (1 << i)) >> i) == 0:
                r1 = r0 + r1
                r0 = r0 + r0
            else:
                r0 = r0 + r1
                r1 = r1 + r1
        return r0

    def __rmul__(self, other):
        return self.__mul__(other)


class ECC(NamedTuple):
    E: FP
    G: ECOps
    n: int

#https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
#https://medium.com/geekculture/euclidean-algorithm-using-python-dc7785bb674a
def extended_euclidean(x, y):
  if y == 0:
    gcd, s, t = x, 1, 0
    return (gcd, s, t)
  else:
    s2, t2, s1, t1 = 1, 0, 0, 1
    while y > 0:
      q = math.floor(x/y)
      r, s, t = (x - y * q), (s2 - q * s1), (t2 - q * t1)
      x, y, s2, t2, s1, t1 = y, r, s1, t1, s, t
    gcd, s, t = x, s2, t2
    return (gcd, s, t)


def modinv(a, m):
    g, x, y = extended_euclidean(a, m)
    return x % m


def get_msg_hash(msg):
    return int.from_bytes(sha256(msg).digest(), "big")

def build_ecc():
    secp256k1_dict = Secp256k1Params().get_secp256k1params()
    secp256k1 = namedtuple("secp256k1", secp256k1_dict)(**secp256k1_dict)
    if (secp256k1.Gx ** 3 + 7 - secp256k1.Gy ** 2) % secp256k1.p != 0:
        print("exception ...")
        sys.exit()

    curve = FP(secp256k1.p, secp256k1.a, secp256k1.b)
    G = ECOps(curve, secp256k1.Gx, secp256k1.Gy)
    assert (G * secp256k1.n) == G.get_identity()
    return ECC(curve, G, secp256k1.n)


class ECDSASignature(NamedTuple):
    r: int
    s: int

class ECDSAPrivKey(NamedTuple):
    ecc: ECC
    secret: int

    def get_pubkey(self):
        W = self.secret * self.ecc.G
        pub = ECDSAPubKey(self.ecc, W)
        return pub


class ECDSAPubKey(NamedTuple):
    ecc: ECC
    W: ECOps

def generate_priv_ecc_key(ecc, fname):
    
    rbytes = os.urandom(32)
    rint = int.from_bytes(rbytes, 'big')
    while True:
        if 1 < rint < (ecc.n - 1):
            break
        rbytes = os.urandom(32)
        rint = int.from_bytes(32, 'big')

    if DEBUG:
        pass
    else:
        s_file = open(fname, "wb")
        s_file.write(rbytes)
        s_file.close()


def generate_public_ecc_key(ecc, privKey, fname):
    privKey = ECDSAPrivKey(ecc, privKey)
    pub = privKey.get_pubkey()
    if DEBUG:
        return pub
    else:
        pub_file = open(fname, 'wb')
        pickle.dump(pub, pub_file)
        pub_file.close()


def sign_msg(private_key, ecc, msg, fname, k=None):
    priv = ECDSAPrivKey(ecc, private_key)

    G = priv.ecc.G
    n = priv.ecc.n

    if DEBUG:
        msg_hash = msg
    else:
        msg_hash = get_msg_hash(msg)

        kbytes = os.urandom(32)
        k = int.from_bytes(kbytes, 'big')
        while True:
            if 1 < k < (n-1):
                break
            kbytes = os.urandom(32)
            k = int.from_bytes(kbytes, 'big')

    while True:
        V = k * G
        r = V.x % n
        if r == 0:
            continue
        s = (modinv(k, n) * (msg_hash + priv.secret * r)) % n
        if s == 0:
            continue
        break

    signature = ECDSASignature(r, s)
    if DEBUG:
        return signature
    else:
        sigfile = open(fname, 'wb')
        pickle.dump(signature, sigfile)
        sigfile.close()


def verify_msg(pub, msg, signature):
    n = pub.ecc.n
    G = pub.ecc.G

    r = signature.r
    s = signature.s

    if DEBUG:
        msg_hash = msg
    else:
        msg_hash = get_msg_hash(msg)
    s_inv = modinv(s, n)

    u1 = (msg_hash * s_inv) % n
    u2 = (r * s_inv) % n

    Pxy = u1 * G + u2 * pub.W
    
    if (Pxy.x % n) == r:
        return True
    else:
        return False


def main():
    MIN_PYTHON = (3, 6)
    if sys.version_info < MIN_PYTHON:
        sys.exit("Python %s.%s or later is required.\n" % MIN_PYTHON)

    ecc = build_ecc()
    global DEBUG
    if len(sys.argv) == 1:
        DEBUG = True
        
        d = debugcls()
        tv = d.testvector()
        generate_priv_ecc_key(ecc, None) #assume pass

        for i in range(0, len(tv)):
            print("=> test vector: ", i)
            pk_int = tv[i]['pk']
            pub = generate_public_ecc_key(ecc, pk_int, None)
            assert tv[i]['pubk_x'] == pub.W.x, "tv failed"
            assert tv[i]['pubk_y'] == pub.W.y, "tv failed"
            
            signature = sign_msg(pk_int, ecc, tv[i]['msg_hash'], None, tv[i]['k'])
            assert tv[i]['r'] == signature.r, "tv failed"
            assert tv[i]['s'] == signature.s, "tv failed"

            is_ok = verify_msg(pub, tv[i]['msg_hash'], signature)
            assert is_ok == True, "tv failed"

            print("\tpassed")
        print("test vectors passed")
    else:
        parser = argparse.ArgumentParser()

        subparser = parser.add_subparsers(dest='op')

        gen_priv_key = subparser.add_parser('gen_priv_key')
        gen_pub_key = subparser.add_parser('gen_pub_key')

        sign = subparser.add_parser('sign')
        verify = subparser.add_parser('verify')

        gen_priv_key.add_argument('--pkf', type=str, required=True)
        
        gen_pub_key.add_argument('--pkf', type=str, required=True)
        gen_pub_key.add_argument('--pubf', type=str, required=True)

        sign.add_argument('--pkf', type=str, required=True)
        sign.add_argument('--inputf', type=str, required=True)
        sign.add_argument('--sigf', type=str, required=True)

        verify.add_argument('--pubf', type=str, required=True)
        verify.add_argument('--inputf', type=str, required=True)
        verify.add_argument('--sigf', type=str, required=True)
        
        args = parser.parse_args()

        if args.op == 'gen_priv_key':
            print('private key file: ', args.pkf)
            generate_priv_ecc_key(ecc, args.pkf)
        elif args.op == 'gen_pub_key':
            print('private key file: ', args.pkf)
            print('public key file: ', args.pubf)

            pkf = open(args.pkf, "rb")
            pk_bytes = pkf.read(32)
            pkf.close()
            pk_int = int.from_bytes(pk_bytes, 'big')
            generate_public_ecc_key(ecc, pk_int, args.pubf)

        elif args.op == 'sign':
            msg = None
            print('private key file: ', args.pkf)
            print('file name: ', args.inputf)
            print('signature file: ', args.sigf)

            pkf = open(args.pkf, "rb")
            pk_bytes = pkf.read(32)
            pkf.close()
            pk_int = int.from_bytes(pk_bytes, 'big')

            input_file = open(args.inputf, "r")
            msg = input_file.read().encode('utf-8')
            input_file.close()

            sign_msg(pk_int, ecc, msg, args.sigf, None)


        elif args.op == 'verify':
            msg = None
            print('public key file: ', args.pubf)
            print('file name: ', args.inputf)
            print('signature file: ', args.sigf)

            pubf = open(args.pubf, "rb")
            pubKey = pickle.load(pubf)
            pubf.close()

            sigf = open(args.sigf, "rb")
            sig = pickle.load(sigf)
            sigf.close()

            input_file = open(args.inputf, "r")
            msg = input_file.read().encode('utf-8')
            input_file.close()

            is_ok = verify_msg(pubKey, msg, sig)
            print("Verify: ", is_ok)


if __name__ == "__main__":
    main()
