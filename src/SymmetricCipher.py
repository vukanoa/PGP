from abc import ABC, abstractmethod
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.exceptions import InvalidTag
import os

from hash import SHA3_256Wrapper

class SymmetricCipher(ABC):
    @abstractmethod
    def encrypt(self, key, plaintext):
        pass

    @abstractmethod
    def decrypt(self, key, ciphertext):
        pass

    @abstractmethod
    def getAlgorithmCode(self):
        pass

    @abstractmethod
    def generateSessionKey(self):
        pass

    @abstractmethod
    def getSessionKeySize(self):
        pass


class AESCipher(SymmetricCipher):
    @staticmethod
    def encrypt(key, plaintext):
        backend = default_backend()
        iv = os.urandom(16)
        padder = PKCS7(128).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        return iv + ciphertext

    @staticmethod
    def decrypt(key, ciphertext):
        backend = default_backend()
        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext
    
    @staticmethod
    def getAlgorithmCode():
        return b'\xff'
    
    @staticmethod
    def generateSessionKey():
        return os.urandom(16)
    
    @staticmethod
    def getSessionKeySize():
        return 16

class TripleDES(SymmetricCipher):
    @staticmethod
    def encrypt(key, plaintext):
        backend = default_backend()
        iv = os.urandom(8)
        padder = PKCS7(64).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        return iv + ciphertext

    @staticmethod
    def decrypt(key, ciphertext):
        backend = default_backend()
        iv = ciphertext[:8]
        ciphertext = ciphertext[8:]
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = PKCS7(64).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext
    
    @staticmethod
    def getAlgorithmCode():
        return b'\xfe'
    
    @staticmethod
    def generateSessionKey():
        return os.urandom(24)
    
    @staticmethod
    def getSessionKeySize():
        return 24

class AESGCipher(SymmetricCipher):
    @staticmethod
    def encrypt(key, plaintext):
        backend = default_backend()
        iv = os.urandom(12)  # GCM standard recommends 12 bytes
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return iv + encryptor.tag + ciphertext  # Include the auth tag in the output

    @staticmethod
    def decrypt(key, ciphertext):
        backend = default_backend()
        iv = ciphertext[:12]
        tag = ciphertext[12:28]  # GCM tag is 16 bytes
        ciphertext = ciphertext[28:]
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=backend)
        decryptor = cipher.decryptor()
        try:
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext
        except InvalidTag:
            return None

    @staticmethod
    def getAlgorithmCode():
        return b'\xfd'

    @staticmethod
    def generateSessionKey():
        return os.urandom(16)

    @staticmethod
    def getSessionKeySize():
        return 16

    @staticmethod
    def encryptWithPassword(password, plaintext:bytes):
        key = SHA3_256Wrapper.getHashBytes(password)
        return AESGCipher.encrypt(key, plaintext)
    
    @staticmethod
    def decryptWithPassword(password, ciphertext:bytes):
        key = SHA3_256Wrapper.getHashBytes(password)
        return AESGCipher.decrypt(key, ciphertext)

codeToSymmetricCipher = {b'\xff': AESCipher(), b'\xfe': TripleDES(), b'\xfd': AESGCipher()}

'''
key = os.urandom(16)
plaintext = b"hello world hello world hello world"
print("Plaintext:",plaintext)
ciphertext = AESCipher.encrypt(key, plaintext)
print("Ciphertext AESCipher:", ciphertext)
decrypted_text = AESCipher.decrypt(key, ciphertext)
print("Decrypted text:", decrypted_text)

ciphertext = TripleDES.encrypt(key, plaintext)
print("Ciphertext TripleDES:", ciphertext)
decrypted_text = TripleDES.decrypt(key, ciphertext)
print("Decrypted text:", decrypted_text)
'''


'''
# AES-GCM
key = AESGCipher.generateSessionKey()
message = b"BRAVOOOOOOO!"
encrypted_message = AESGCipher.encrypt(key, message)
print(f"Encrypted message: {encrypted_message}")
decrypted_message = AESGCipher.decrypt(key, encrypted_message)
print(f"Decrypted message: {decrypted_message}")
tampered_message = encrypted_message[:12] + os.urandom(16) + encrypted_message[28:]
decrypted_message = AESGCipher.decrypt(key, tampered_message)
print(decrypted_message)
'''
'''
# AES-GCM with password

password = b"123456"
message = b"Hello, World!"
encrypted_message = AESGCipher.encryptWithPassword(password, message)
print(f"Encrypted message: {encrypted_message}")
decrypted_message = AESGCipher.decryptWithPassword(password, encrypted_message)
print(f"Decrypted message: {decrypted_message}")
tampered_message = encrypted_message[:12] + os.urandom(16) + encrypted_message[28:]
decrypted_message = AESGCipher.decryptWithPassword(password, tampered_message)
print(decrypted_message)
'''
