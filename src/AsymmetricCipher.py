from abc import ABC, abstractmethod
from Crypto.PublicKey import RSA
from Crypto.PublicKey import DSA
from Crypto.PublicKey import ElGamal

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Signature import DSS
from Crypto.Random import get_random_bytes

from hash import SHA1Wrapper
from ELGAMAL import ElGamalHelper

from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Random import random
from Crypto.Util.number import GCD


class AsymmetricCipher(ABC):

    @abstractmethod
    def encrypt(self, plaintext, public_key):
        pass

    @abstractmethod
    def verify(self, hash, signature, public_key):
        pass

    @abstractmethod
    def decrypt(self, ciphertext, private_key):
        pass

    @abstractmethod
    def sign(self, hash, private_key):
        pass

    @abstractmethod
    def getAlgorithmCode(self):
        pass

    @abstractmethod
    def verifyTwoOctets(self, octets, signature, public_key):
        pass

class RSACipher(AsymmetricCipher):

    @staticmethod
    def encrypt(plaintext, public_key):
        cipher = PKCS1_OAEP.new(public_key)
        return cipher.encrypt(plaintext)

    @staticmethod
    def verify(hash, signature, public_key):
        try:
            return PKCS1_v1_5.new(public_key).verify(hash, signature)
        except (ValueError, TypeError):
            return False

    @staticmethod
    def decrypt(ciphertext, private_key):
        cipher = PKCS1_OAEP.new(private_key)
        return cipher.decrypt(ciphertext)

    @staticmethod
    def sign(hash, private_key):
        signature = PKCS1_v1_5.new(private_key).sign(hash)
        return signature
    
    @staticmethod
    def getAlgorithmCode():
        return b'\x01'
    
    @staticmethod
    def verifyTwoOctets(octets, signature, public_key):

        # Verify that the first two octets are same as the first two octets of the hash
        octets = octets[:2]

        return octets == hash
    
    
class ElGamalDSAKey:
    def __init__(self, ElgamalKey : ElGamal.ElGamalKey, DSAKey : DSA.DsaKey, size_in_bits = None):
        self.size = size_in_bits
        self.ElgamalKey = ElgamalKey
        self.DSAKey = DSAKey

    def export_key(self, format="PEM", passphrase=None, pkcs=None, protection=None):
        if format == "DER":
            return self.DSAKey.export_key(format, passphrase)
        elgamalExport = ElGamalHelper.export_key(self.ElgamalKey, passphrase)
        
        return self.DSAKey.export_key(format,pkcs8=pkcs,protection=protection ,passphrase=passphrase) +b'\n'+ elgamalExport
    
    def import_key(key, passphrase=None):
        # Write analog to RSAKey
        # Separate DSA and ElGamal keys

        # Find secound begin
        begin = key.find(b"-----BEGIN")
        begin = key.find(b"-----BEGIN", begin+1)

        # Separate on begin
        dsaPem = key[:begin]
        elgamalPem = key[begin:]
        # print(dsaPem)
        # print(elgamalPem)

        try:
            ElgamalKey = ElGamalHelper.import_key(elgamalPem, passphrase=passphrase)
        except:
            print("Failed to import ElGamal key")
        try:
            DSAKey = DSA.import_key(dsaPem, passphrase=passphrase)
        except:
            print("Failed to import DSA key")
        return ElGamalDSAKey(ElgamalKey, DSAKey, size_in_bits=1024)



    def public_key(self):
        return ElGamalDSAKey(self.ElgamalKey.publickey(), self.DSAKey.public_key(), self.size)
    
    def size_in_bits(self):
        return self.size
    
    def get_elgamal_p(self):
        return self.ElgamalKey.p

    def get_elgamal_g(self):
        return self.ElgamalKey.g
    
    def get_elgamal_public_key(self):
        return self.ElgamalKey.publickey().y
    
    def get_elgamal_private_key(self):
        return self.ElgamalKey.x
    
    @staticmethod
    def generate(bits, randfunc=None):
        import os
        DSAKey = DSA.generate(bits, randfunc)
        ElgamalKey = ElGamal.generate(bits,  os.urandom)

        return ElGamalDSAKey(ElgamalKey, DSAKey, bits)


class ElGamalDSACipher(AsymmetricCipher):
    # DSA     is for signing    and verification only
    # ElGamal is for encryption and decryption   only

    @staticmethod
    def encrypt(plaintext, public_key): # ElGamal
        p = public_key.get_elgamal_p()
        g = public_key.get_elgamal_g()
        y = public_key.get_elgamal_public_key()

        plaintext_int = bytes_to_long(plaintext)
        while 1:
            k = random.StrongRandom().randint(1, int(p) - 1)
            if GCD(k,p-1)==1: break

        # k = random.randint(1, int(p) - 1)
        c1 = pow(g, k, p)
        c2 = (plaintext_int * pow(int(y), k, int(p))) % int(p)

        ciphertext = (c1, c2)

        # Ciphertext to bytes
        c1 = long_to_bytes(c1)
        c2 = long_to_bytes(c2)

        # Make ciphertext parsable
        ciphertext = c1 + b'   ' + c2

        return ciphertext

    @staticmethod
    def verify(hash, signature, public_key):#DSA
        verifier = DSS.new(public_key.DSAKey, 'fips-186-3')
        try:
            verifier.verify(hash, signature)
            return True
        except ValueError:
            return False

    @staticmethod
    def decrypt(ciphertext, private_key):  # ElGamal
        ciphertext = ciphertext.split(b'   ')
        p = int(private_key.get_elgamal_p())
        x = int(private_key.get_elgamal_private_key())
        c1, c2 = ciphertext
        c1 = bytes_to_long(c1)
        c2 = bytes_to_long(c2)

        # Convert IntegerCustom objects to integers
        c1 = int(c1)
        c2 = int(c2)

        plaintext_int = (c2 * pow(c1, p - 1 - x, p)) % p
        plaintext = long_to_bytes(plaintext_int)

        return plaintext

    @staticmethod
    def sign(hash, private_key):#DSA
        signer = DSS.new(private_key.DSAKey, 'fips-186-3')
        return signer.sign(hash)
    
    @staticmethod
    def getAlgorithmCode():
        return b'\x02'
    
    @staticmethod
    def verifyTwoOctets(octets, signature, public_key): # DSA
        pass



codeToAsymmetricCipher = {b'\x01': RSACipher(), b'\x02': ElGamalDSACipher()}

if __name__ == "__main__":

    # Tests for ElGamalDSA
    key = ElGamalDSAKey.generate(1024)

    ct = ElGamalDSACipher.encrypt(b"plaintext", key)
    print(ElGamalDSACipher.decrypt(ct, key))
    # print(ct)

    txt = b"TESTETSTEST"
    print("\n\nAAAAAAAAAAAAAAAAAAAA\n\n")

    hash = SHA1Wrapper.getHash(txt)
    signature = ElGamalDSACipher.sign(hash, key)
    print(ElGamalDSACipher.verify(hash, signature, key))

    # Modify signature
    signature = signature[:-1] + b'\x00'
    print(ElGamalDSACipher.verify(hash, signature, key))


    print(key.export_key(passphrase=b"123", pkcs=8, protection="PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC"))
