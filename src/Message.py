import base64
import time
import zlib
from Keyring import Keyring 

import copy

from Crypto.PublicKey import RSA, ElGamal, DSA
from AsymmetricCipher import RSACipher, codeToAsymmetricCipher
from SymmetricCipher import AESCipher, TripleDES, codeToSymmetricCipher, SymmetricCipher
from Key import PrivateKeyWrapper
from hash import SHA1Wrapper

class Message():
    
    message = None
    filename = None
    timestamp = None

    loadedBytes = None
    verificationBundle = None

    base64 = False
    zipped = False
    encrypted = False
    signed = False

    decryptionFailed = False

    recipientKeyId = None

    def __init__(self, arg1:bytes, arg2 = None, arg3 = None):
        if type(arg2) is bytes:
            self.__initNewMSG__(arg1, arg2)
        else:
            self.__initLoadMsg__(arg1, arg2, arg3)

    def __initNewMSG__(self,filename: bytes, message: bytes):
        self.message = message
        self.filename = filename
        timestamp = int(time.time())
        self.timestamp = timestamp.to_bytes(4, byteorder='big')#4bytes
    
    def __initLoadMsg__(self, loadedBytes: bytes, recipientPrivateKey = None, password = None):
        self.loadedBytes = loadedBytes
        self.__loadMessage(recipientPrivateKey, password)

    def __loadMessage(self, recipientPrivateKey, password):
        if self.loadedBytes is None:
            return
        if self.loadedBytes[0:3] == 'r64':
            self.base64 = True
            self.loadedBytes = self.radix64Decode(self.loadedBytes)

        if self.loadedBytes[0:4] == b'encr':
            self.encrypted = True
            if recipientPrivateKey is None or password is None:
                self.recipientKeyId = self.getEncryptedMessageReceiverKeyId()
                self.decryptionFailed = True
                return

            if recipientPrivateKey.checkPassword(password) == False:
                self.decryptionFailed = True
                return

            self.loadedBytes = self.decryptMessage(self.loadedBytes, recipientPrivateKey, password)

        if self.loadedBytes[0:3] == b'zip':
            self.zipped = True
            self.loadedBytes = self.decompressMessage(self.loadedBytes)

        if self.loadedBytes[0:6] == b'signed':
            self.signed = True
            self.verificationBundle = copy.deepcopy(self.loadedBytes)
            signatureLength = self.loadedBytes[21:23]
            signatureLength = int.from_bytes(signatureLength, byteorder='big')
            self.loadedBytes = self.loadedBytes[23+signatureLength:]



        self.filename = self.loadedBytes.split(b'\0')[0]
        self.loadedBytes = self.loadedBytes[len(self.filename)+1:]
        self.timestamp = self.loadedBytes[:4]
        self.message = self.loadedBytes[4:]
        self.loadedBytes = None

    def createOuputBytes(self, signed=False, encrypted=False, zipped=False, base64=False,senderKey=None, password:bytes = None , receiverKey=None, symmetricCipher : SymmetricCipher = None):
        self.loadedBytes = self.filename+b'\0'+ self.timestamp + self.message
        if signed:
            self.loadedBytes = self.signMessage(self.loadedBytes, senderKey, password)
        if zipped:
            self.loadedBytes = self.compressMessage(self.loadedBytes)
        if encrypted:
            self.loadedBytes = self.encryptMessage(self.loadedBytes, receiverKey, symmetricCipher)
        if base64:
            self.loadedBytes = self.radix64Encode(self.loadedBytes)
        return self.loadedBytes

    def encryptMessage(self, message, receiverKey, encryptionAlgorithm : SymmetricCipher):
        # Crypted header 
        # Keyid
        # Symmetric cipher
        # Asymmetric cipher
        # Encrypted session key
        # Encrypted message
        sessionKey = encryptionAlgorithm.generateSessionKey()
        encryptedSessionKey = receiverKey.encrypt(sessionKey)
        encryptedMessage = encryptionAlgorithm.encrypt(sessionKey, message)

        return b'encr'+receiverKey.getKeyId()+encryptionAlgorithm.getAlgorithmCode()+receiverKey.getAlgorithmCode()+len(encryptedSessionKey).to_bytes(4, byteorder='big')+encryptedSessionKey+encryptedMessage

    def decryptMessage(self, message, recipientKey, password):
        if message[0:4] != b'encr':
            return message

        keyid = message[4:12]
        if keyid != recipientKey.getKeyId():
            return None

        encryptionAlgorithm = message[12:13]
        asymmetricAlgorithm = message[13:14]
        if asymmetricAlgorithm != recipientKey.getAlgorithmCode() \
            or encryptionAlgorithm not in codeToSymmetricCipher:
            self.decryptionFailed = True
            return None

        SymmetricCipher = codeToSymmetricCipher[encryptionAlgorithm]
        sessionKeySize = int.from_bytes(message[14:18], byteorder='big')
        encryptedSessionKey = message[18:18+sessionKeySize]
        encryptedMessage = message[18+sessionKeySize:]
        sessionKey = recipientKey.decrypt(encryptedSessionKey, password)

        return SymmetricCipher.decrypt(sessionKey, encryptedMessage)

    def getEncryptedMessageReceiverKeyId(self):
        if self.loadedBytes[0:4] != b'encr':
            return None
        return self.loadedBytes[4:12]
    
    def signMessage(self, message, key, password):
        timestamp = int(time.time())
        timestamp = timestamp.to_bytes(4, byteorder='big') # 4bytes
        
        hash = SHA1Wrapper().getHash(message)
        signature = key.sign(hash, password)
        signatureLength = len(signature).to_bytes(2, byteorder='big')
        hash = SHA1Wrapper().getHashBytes(message)
        keyid = key.getKeyId()

        return b'signed' + key.getAlgorithmCode() + timestamp + keyid + hash[0:2] + signatureLength + signature + message
    
    def verifyMessage(self, keyRing):
        algo = self.verificationBundle[6].to_bytes(1, byteorder='big')
        if self.verificationBundle[0:6] != b'signed' or algo not in codeToAsymmetricCipher:
            return False, None

        timestamp = self.verificationBundle[7:11]
        keyid = self.verificationBundle[11:19]

        key = keyRing.getKeyById(keyid)
        if key is None or key.getAlgorithmCode() != algo:
            return False, None

        hashOctets = self.verificationBundle[19:21] # Find way to use this to avoid hashing if bad message
        signatureLength = self.verificationBundle[21:23]
        signatureLength = int.from_bytes(signatureLength, byteorder='big')
        signature = self.verificationBundle[23:23+signatureLength]
        messageBundle = self.verificationBundle[23+signatureLength:]
        hash = SHA1Wrapper().getHash(messageBundle)

        return key.verify(hash, signature), key

    def compressMessage(self, message):
        return b'zip'+zlib.compress(message)
    
    def decompressMessage(self, message):
        if message[0:3] != b'zip':
            return message
        return zlib.decompress(message[3:])
    
    def radix64Encode(self, message):
        return 'r64'+base64.b64encode(message).decode('ascii')
    
    def radix64Decode(self, message):
        return base64.b64decode(message[3:])
    

if __name__ == "__main__":
    rsa_key = RSA.generate(1024)
    
    private_key = PrivateKeyWrapper(time.time(), rsa_key, "name", "email", RSACipher(), b'123123')

    msg = Message(b"hello", b"Lorem impsum blah blah blah")

    out_mst = msg.createOuputBytes(signed=True, senderKey=private_key, zipped=True, base64=True, encrypted=True, receiverKey=private_key, symmetricCipher=TripleDES(), password=b'123123')
    print(out_mst)

    msg2 = Message(out_mst, private_key, b'123123')

    print("TEST")
    print(msg2.filename)
    print(msg2.timestamp)
    print(msg2.message)

    keyRing = Keyring()
    keyRing.addKey(private_key)

    print("Verify MSG: ",msg2.verifyMessage(keyRing))
