from Crypto.Util.number import *
from Crypto.PublicKey import RSA
import elipticCurveArithmetic as eca
import hashlib
from Crypto.Cipher import AES
import math
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme as pkcs
from Crypto.Hash import SHA256

class new(object):
    def __init__(self):
        # Curve Parameters
        self.curveParams = curveParams()
        self.publicData = publicData()
        self.privateData = privateData()
        self.partnerData = publicData()


    def generateDHKEPrivateValue(self):
        val = getRandomRange(2, self.curveParams.N - 1)
        self.privateData.dhValue = val

        # Confirm that it's the correct value
        order = self.curveParams.N
        if math.gcd(val, order) != 1:
            print('Invalid DHKE Private Value Created, pleas try again!')

        return val

    def generateDHKENonceValue(self):
        val = getRandomRange(2, self.curveParams.N - 1)
        self.privateData.dhNonce = val

        # Confirm that it's the correct value
        order = self.curveParams.N
        if math.gcd(val, order) != 1:
            print('Invalid DHKE Nonce Value Created, pleas try again!')

        return val

    def generateRSAKey(self, numBits=1024):
        key = RSA.generate(numBits)
        self.privateData.rsaKey = key
        self.publicData.rsaKey = key.public_key()

        return key

    def calculatePublicDHKEPoints(self):
        a = self.privateData.dhValue
        Gx = self.curveParams.Gx
        Gy = self.curveParams.Gy
        Q = self.curveParams.Q
        A = self.curveParams.A
        B = self.curveParams.B
        points = eca.multiplyPoint(a, Gx, Gy, Q, A, B)

        self.publicData.dhke_point = points

    def calculatePublicDHKENoncePoints(self):
        a = self.privateData.dhNonce
        Gx = self.curveParams.Gx
        Gy = self.curveParams.Gy
        Q = self.curveParams.Q
        A = self.curveParams.A
        B = self.curveParams.B
        points = eca.multiplyPoint(a, Gx, Gy, Q, A, B)

        self.publicData.dhke_noncepoint = points

    def generateRsaSignature(self, msg):
        key = self.privateData.rsaKey
        msgHashed = SHA256.new(str(msg).encode('utf-8'))
        sigScheme = pkcs(key)
        sig = sigScheme.sign(msgHashed)

        # Confirm message is smaller than n
        if key.n <= int(msgHashed.hexdigest(), 16):
            print('Message is larger than n. Please use a larger n')

        # Return stuff
        return msg, sig

    def genereateEncryptedMessage(self, msg):
        # Will encrypt and generate the tag
        cipher = AES.new(self.privateData.key, AES.MODE_GCM, nonce=self.privateData.AES_nonce)
        eMsg, tag = cipher.encrypt_and_digest(bytearray(msg.encode('utf-8')))
        return eMsg, tag

    def verifyRsaSignature(self, msg, sig):
        verified = False
        key = self.partnerData.rsaKey
        msgHash = SHA256.new(str(msg).encode('utf-8'))
        sigScheme = pkcs(key)
        try:
            sigScheme.verify(msgHash, sig)
            verified = True
        except:
            verified = False

        return verified

    def receiveEncryptedMessage(self, msgIn, tag=-1):
        cipher = AES.new(self.privateData.key, AES.MODE_GCM, nonce=self.privateData.AES_nonce)
        verified = False
        if tag != -1:
            # Decrypt AND verify
            try:
                msg = convertBytesToString(cipher.decrypt_and_verify(msgIn, tag))
                verified = True
            except:
                cipher = AES.new(self.privateData.key, AES.MODE_GCM, nonce=self.privateData.AES_nonce)
                msg = convertBytesToString(cipher.decrypt(msgIn))
        else:
            # Decrypt
            msg = convertBytesToString(cipher.decrypt(msgIn))
        return msg, verified

    def computeSecretKeys(self):
        a = self.privateData.dhValue
        X = self.partnerData.dhke_point[0]
        Y = self.partnerData.dhke_point[1]
        Q = self.curveParams.Q
        A = self.curveParams.A
        B = self.curveParams.B

        S = eca.multiplyPoint(a, X, Y, Q, A, B)

        self.privateData.key = hashlib.sha256(str(S[0]).encode('utf-8')).digest()

        return S

    def computeSecretNonce(self):
        a = self.privateData.dhNonce
        X = self.partnerData.dhke_noncepoint[0]
        Y = self.partnerData.dhke_noncepoint[1]
        Q = self.curveParams.Q
        A = self.curveParams.A
        B = self.curveParams.B

        S = eca.multiplyPoint(a, X, Y, Q, A, B)

        self.privateData.AES_nonce = hashlib.sha256(str(S[0]).encode('utf-8')).digest()

        return S

class privateData(object):
    def __init__(self):
        self.rsaKey = []
        self.dhValue = []
        self.dhNonce = []
        self.key = []
        self.AES_nonce = []

class publicData(object):
    def __init__(self):
        self.dhke_point = []
        self.rsaKey = []
        self.dhke_noncepoint = []

class curveParams(object):
    def __init__(self):
        Q = []
        A = []
        B = []
        N = []
        Gx = []
        Gy = []
        curveName = []

    def defineEllipticCurve(self, ecIn):
        # For list of approved curves please see https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
        # For other curve information please see https://neuromancer.sk/std/
        if ecIn == 'P-192' or ecIn == 'secp192r1':
            self.Q = 0xfffffffffffffffffffffffffffffffeffffffffffffffff
            self.A = 0xfffffffffffffffffffffffffffffffefffffffffffffffc
            self.B = 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1
            self.Gx = 0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012
            self.Gy = 0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811
            self.N = 0xffffffffffffffffffffffff99def836146bc9b1b4d22831
        elif ecIn == 'P-224' or ecIn == 'secp224r1':
            self.Q = 0xffffffffffffffffffffffffffffffff000000000000000000000001
            self.A = 0xfffffffffffffffffffffffffffffffefffffffffffffffffffffffe
            self.B = 0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4
            self.Gx = 0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21
            self.Gy = 0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34
            self.N = 0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d
        elif ecIn == 'P-256' or ecIn == 'secp256r1':
            self.Q = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
            self.A = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
            self.B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
            self.Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
            self.Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
            self.N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
        elif ecIn == 'P-384' or ecIn == 'secp384r1':
            self.Q = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff
            self.A = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc
            self.B = 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef
            self.Gx = 0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7
            self.Gy = 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f
            self.N = 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973
        elif ecIn == 'P-521' or ecIn == 'secp521r1':
            self.Q = 0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
            self.A = 0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc
            self.B = 0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00
            self.Gx = 0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66
            self.Gy = 0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650
            self.N = 0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409
        elif ecIn == 'brainpoolP512t1':
            self.Q = 0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3
            self.A = 0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f0
            self.B = 0x7cbbbcf9441cfab76e1890e46884eae321f70c0bcb4981527897504bec3e36a62bcdfa2304976540f6450085f2dae145c22553b465763689180ea2571867423e
            self.Gx = 0x640ece5c12788717b9c1ba06cbc2a6feba85842458c56dde9db1758d39c0313d82ba51735cdb3ea499aa77a7d6943a64f7a3f25fe26f06b51baa2696fa9035da
            self.Gy = 0x5b534bd595f5af0fa2c892376c84ace1bb4e3019b71634c01131159cae03cee9d9932184beef216bd71df2dadf86a627306ecff96dbb8bace198b61e00f8b332
            self.N = 0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069
        elif ecIn == 'brainpoolP512r1':
            self.Q = 0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3
            self.A = 0x7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca
            self.B = 0x3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723
            self.Gx = 0x81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822
            self.Gy = 0x7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892
            self.N = 0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069
        else:
            print('Invalid elliptic curve entered.')
            return
        self.curveName = ecIn

def convertBytesToString(bytesIn):
    strOut = ''
    for i in bytesIn:
        strOut += chr(i)
    return strOut