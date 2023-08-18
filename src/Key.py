from AsymmetricCipher import *
from datetime import datetime
from SymmetricCipher import AESGCipher
import pickle
import base64

metadataBegin = b"-----BEGIN METADATA-----\n"
metadataEnd = b"-----END METADATA-----\n"

class PublicKeyWrapper():
    def __init__(self, timestamp : datetime, publicKey : object , name: str, email: str, algorithm: AsymmetricCipher):
        self.timestamp = timestamp
        self.keyId = publicKey.public_key().export_key("DER")[:8]
        self.publicKey = publicKey
        self.name = name
        self.email = email
        self.algorithm = algorithm
        self.size = publicKey.size_in_bits()

    def encrypt(self, plaintext):
        return self.algorithm.encrypt(plaintext, self.publicKey)

    def verify(self, hash, signature):
        return self.algorithm.verify(hash, signature, self.publicKey)
    
    def getKeyId(self):
        return self.keyId
    
    def getKeyIdHexString(self):
        return self.keyId.hex().upper()
    
    def getAlgorithmCode(self):
        return self.algorithm.getAlgorithmCode()
    
    def _importPrivateKey(self, key):
        if self.algorithm.getAlgorithmCode() == RSACipher.getAlgorithmCode():
            return RSA.import_key(key)
        elif self.algorithm.getAlgorithmCode() == ElGamalDSACipher.getAlgorithmCode():
            print(key)
            return ElGamalDSAKey.import_key(key)
    

    def __getstate__(self):
        state = self.__dict__.copy()
        # Remove any non-picklable attributes
        state['publicKey'] = state['publicKey'].export_key()

        return state

    def __setstate__(self, state):
        self.__dict__.update(state)

        # Restore the non-picklable attribute
        self.publicKey = self._importPrivateKey(state['publicKey'])

    def _exportMetadata(self):
        
        state = self.__getstate__()
        if 'publicKey' in state:
            del state['publicKey']
        if 'privateKey' in state:
            del state['privateKey']
        return metadataBegin+ base64.encodebytes(pickle.dumps(state))+metadataEnd

    @staticmethod
    def _importMetadata(data):
        begin = data.find(metadataBegin)
        end = data.find(metadataEnd)
        if begin != -1 and end != -1:
            state = pickle.loads(base64.decodebytes(data[begin+len(metadataBegin):end]))
            return True, state
        return False, None

    def exportPublicKeyPem(self):
        return self._exportMetadata()+self.publicKey.export_key("PEM")
    
    def exportPublicKeyToFile(self, filename):
        with open(filename, "wb") as f:
            f.write(self.exportPublicKeyPem())
            return True
        return False
    
    @staticmethod
    def importPublicKeyPem(data):
        isMetadata, state = PublicKeyWrapper._importMetadata(data)
        if not isMetadata:
            return False, None
        
        data = data[data.find(metadataEnd)+len(metadataEnd):]

        # print(data)
        try:
            publicKey = RSA.import_key(data)
            return True, PublicKeyWrapper(state['timestamp'], publicKey, state['name'], state['email'], RSACipher())
        except:
            try:
                publicKey = ElGamalDSAKey.import_key(data)
                return True, PublicKeyWrapper(state['timestamp'], publicKey, state['name'], state['email'], ElGamalDSACipher())
            except:
                False, None

    @staticmethod
    def importPublicKeyFromFile(filename):
        with open(filename, "rb") as f:
            data = f.read()
            return PublicKeyWrapper.importPublicKeyPem(data)
    
    # Check if key in file is private or public
    @staticmethod
    def isPrivateKey(filename):
        with open(filename, "rb") as f:
            data = f.read()
            return data.find(b"PRIVATE") != -1

class PrivateKeyWrapper(PublicKeyWrapper):
    def __init__(self, timestamp : datetime, privateKey : object , name: str, email: str, algorithm: AsymmetricCipher, password: bytes):
        publicKey = privateKey.public_key()
        super().__init__(timestamp, publicKey, name, email, algorithm)
        self.privateKey = privateKey
        self.privateKey = self.__encryptPrivateKey(password)
        self.size = privateKey.size_in_bits()

    
    def __decryptPrivateKey(self, password):
        key = AESGCipher.decryptWithPassword(password, self.privateKey)
        if key!=None:
            # print(key)
            return PublicKeyWrapper._importPrivateKey(self,key)
        return None

    def __encryptPrivateKey(self, password):
        return AESGCipher.encryptWithPassword(password, self.privateKey.export_key())


    # Private key must have
    def decrypt(self, ciphertext, password):
        data = None
        privateKey = self.__decryptPrivateKey(password)
        if privateKey is not None:
            data = self.algorithm.decrypt(ciphertext, privateKey)
        return data

    def sign(self, hash, password):
        data = None
        privateKey = self.__decryptPrivateKey(password)
        if privateKey is not None:
            data = self.algorithm.sign(hash, privateKey)
        return data
    
    def exportPrivateKeyPem(self, password):
        data = None
        privateKey = self.__decryptPrivateKey(password)
        
        if privateKey is not None:
            data = privateKey.export_key("PEM", pkcs=8, protection="scryptAndAES128-CBC", passphrase=password)
            data = PublicKeyWrapper._exportMetadata(self)+data
        return data
    
    def exportPrivateKeyToFile(self, filename, password):
        data = self.exportPrivateKeyPem(password)
        if data != None:
            with open(filename, "wb") as f:
                f.write(self.exportPrivateKeyPem(password))
                return True
        return False
    
    def checkPassword(self, password):
        return self.__decryptPrivateKey(password) is not None
    
    @staticmethod
    def importPrivateKeyPem(data, password):
        isMetadata, state = PublicKeyWrapper._importMetadata(data)
        if not isMetadata:
            return False, None
        
        data = data[data.find(metadataEnd)+len(metadataEnd):]
        try:
            privateKey = RSA.import_key(data, passphrase=password)
            return True, PrivateKeyWrapper(state['timestamp'], privateKey, state['name'], state['email'], RSACipher(), password)
        except:
            try:
                #print(data)
                privateKey = ElGamalDSAKey.import_key(data, passphrase=password)
                return True, PrivateKeyWrapper(state['timestamp'], privateKey, state['name'], state['email'], ElGamalDSACipher(), password)
            except:
                return False, None

    @staticmethod
    def importPrivateKeyFromFile(filename, password):
        with open(filename, "rb") as f:
            data = f.read()
            return PrivateKeyWrapper.importPrivateKeyPem(data, password)
        


if __name__ == "__main__":
    # Example 1
    timestamp1 = datetime.now()
    rsa_key1 = RSA.generate(1024)
    key1 = PrivateKeyWrapper(timestamp1, rsa_key1, "Pera", "pera@pera.com", RSACipher(), b"123")
    key1.exportPrivateKeyToFile("test1.pem", b"123")
    status, key1 = PrivateKeyWrapper.importPrivateKeyFromFile("test1.pem", b"123")

    print(key1.__getstate__())
    key1pub = PublicKeyWrapper(timestamp1, rsa_key1.public_key(), "Pera", "pera@pera.com", RSACipher())
    key1pub.exportPublicKeyToFile("test1pub.pem")
    status, key1pub = PublicKeyWrapper.importPublicKeyFromFile("test1pub.pem")
    print(key1pub.__getstate__())


    # Example 2 - ElGamal
    timestamp2 = datetime.now()
    elgamal_key2 = ElGamalDSAKey.generate(1024)
    key2 = PrivateKeyWrapper(timestamp2, elgamal_key2, "Pera", "pera@pera.com", ElGamalDSACipher(), b"123")

    # Encrypt and Decrypt
    plaintext = b"Hello world!"
    ciphertext = key2.encrypt(plaintext)

    print("CT", ciphertext)
    print("PT", key2.decrypt(ciphertext, b"123"))

    # Sign and Verify
    hash = SHA1Wrapper.getHash(plaintext)
    signature = key2.sign(hash, b"123")

    print(signature)
    print(key2.verify(hash, signature))
    print(key1.verify(hash, signature))

	# Export
    key2.exportPrivateKeyToFile("test2.pem", b"123")
    status, key2 = PrivateKeyWrapper.importPrivateKeyFromFile("test2.pem", b"123")
    print(key2.__getstate__())
