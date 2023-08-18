from abc import ABC
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from Crypto.Hash import SHA1
from Crypto.Hash import SHA3_256

class HashWrapper(ABC):
    @staticmethod
    def getHashBytes(byts : bytes):
        pass
    @staticmethod
    def getHash(byts : bytes):
        pass

class SHA1Wrapper(HashWrapper):
    @staticmethod
    def getHashBytes(byts : bytes):
        digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
        digest.update(byts)
        return digest.finalize()
    
    @staticmethod
    def getHash(byts : bytes):
        return SHA1.new(byts)
    
class SHA3_256Wrapper(HashWrapper):
    @staticmethod
    def getHashBytes(byts : bytes):
        digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
        digest.update(byts)
        return digest.finalize()
    
    @staticmethod
    def getHash(byts : bytes):
        return SHA3_256.new(byts)

'''
s = "Hello, World!"
SHA1 = SHA1()
b = SHA1.getHash(s)

print(b) # returns bytes
'''
