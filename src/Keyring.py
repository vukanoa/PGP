from Key import PublicKeyWrapper, PrivateKeyWrapper
from AsymmetricCipher import *
from datetime import datetime
from Crypto.PublicKey import RSA
import pickle
from SymmetricCipher import AESGCipher

class Keyring:
    def __init__(self, private: bool = False):
        self._keys = []
        self._private = private

    def addKey(self, key):
        self._keys.append(key)

    def getKeyById(self, keyID):
        for key in self._keys:
            if keyID == key.getKeyId():
                return key
        
        return None
    
    def getKeyByKeyIdHexString(self, keyID):
        for key in self._keys:
            if keyID == key.getKeyIdHexString():
                return key
        
        return None
    
    def removeKeyByKeyIdHexString(self, keyID):
        for key in self._keys:
            if keyID == key.getKeyIdHexString():
                self._keys.remove(key)
                return True
        
        return False
    
    def isPrivate(self):
        return self._private
    
    def getKeys(self):
        return self._keys

    def __serialize(self):
        return pickle.dumps(self)
    
    @staticmethod
    def __deserialize(byts):
        return pickle.loads(byts)
    
    def saveToFile(self, filename, password):
        with open(filename, "wb") as f:
            encrypted_bytes = AESGCipher.encryptWithPassword(password, self.__serialize())
            f.write(encrypted_bytes)
    
    @staticmethod
    def loadFromFile(filename, password):
        with open(filename, "rb") as f:
            encrypted_bytes = f.read()
            decrypted_bytes = AESGCipher.decryptWithPassword(password, encrypted_bytes)
            if decrypted_bytes is None:
                return None
            return Keyring.__deserialize(decrypted_bytes)


if __name__ == "__main__":
    # Create an instance of KeyringPR (Private Keyring)
    keyring = Keyring(True)

    # Example 1
    timestamp1 = datetime.now()
    rsa_key1 = RSA.generate(1024)
    key1 = PrivateKeyWrapper(timestamp1, rsa_key1, "Pera", "example1@example.com", RSACipher(), b"123")
    keyring.addKey(key1)

    # Example 2
    timestamp2 = datetime.now()
    rsa_key2 = RSA.generate(1024)
    key2 = PrivateKeyWrapper(timestamp2, rsa_key2, "Zika", "example2@example.com", RSACipher(), b"123")
    keyring.addKey(key2)

    # Example 3
    timestamp3 = datetime.now()
    rsa_key3 = RSA.generate(1024)
    key3 = PrivateKeyWrapper(timestamp3, rsa_key3, "Mika", "example3@example.com", RSACipher(), b"123")
    keyring.addKey(key3)

    # Example 4
    timestamp4 = datetime.now()
    rsa_key4 = RSA.generate(1024)
    key4 = PrivateKeyWrapper(timestamp4, rsa_key4, "Laza", "example4@example.com", RSACipher(), b"123")
    print(key4.getKeyIdHexString())
    keyring.addKey(key4)

    # Eample for saveToFile and loadFromFile
    keyring.saveToFile("keyring.bin", b"123456")
    keyring_loaded = Keyring.loadFromFile("keyring.bin", b"123456")
    keykey = keyring_loaded.getKeyById(key4.getKeyId())
    print(keykey.getKeyIdHexString())
    print(keykey.exportPublicKeyPem())
    print(keykey.exportPrivateKeyPem(b"123"))
    keykey.exportPublicKeyToFile("keykeypub.pem")
    keykey.exportPrivateKeyToFile("keykeypriv.pem", b"123")

    # Create new keyring
    password = b"123"
    privateKeyring = Keyring(True)
    publicKeyring = Keyring(False)

    privateKeyring.saveToFile("private_keyring.bin", password)
    publicKeyring.saveToFile("public_keyring.bin", password)
    
    # Loading keys default
    password = b"123"
    privateKeyring = Keyring.loadFromFile("private_keyring.bin", password)
    publicKeyring = Keyring.loadFromFile("public_keyring.bin", password)

    if privateKeyring is None or publicKeyring is None:
        print("Wrong password")
