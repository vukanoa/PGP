from typing import Optional
from Crypto.PublicKey import ElGamal
from Crypto import Random
from Crypto.Util import asn1
import base64
from SymmetricCipher import AESGCipher
import pickle
from Crypto.Math._IntegerGMP import IntegerGMP

class elgamalPickle(ElGamal.ElGamalKey):
    def __init__(self, p, g, y, x=None):
        self.p = p
        self.g = g
        self.y = y
        self.x = x

    def __getstate__(self):
        state = self.__dict__.copy()
        state['p'] = int(self.p)
        state['g'] = int(self.g)
        state['y'] = int(self.y)
        if state['x'] is not None:
            state['x'] = int(self.x)
        return state
    
    def __setstate__(self, state):
        state['p'] = IntegerGMP(state['p'])
        state['g'] = IntegerGMP(state['g'])
        state['y'] = IntegerGMP(state['y'])
        if state['x'] is not None:
            state['x'] = IntegerGMP(state['x'])
        self.__dict__.update(state)

class ElGamalHelper:

    def export_key(key, passphrase=None):
        
        private = key.has_private()
        if private:
            key = elgamalPickle(key.p, key.g, key.y, key.x)
        else:
            key = elgamalPickle(key.p, key.g, key.y)
        der = pickle.dumps(key)

        if not(private) and passphrase:
            return "Error: Cannot encrypt a public key!"

        if passphrase:
            der = AESGCipher.encryptWithPassword(passphrase, der)
        
        pem_data = base64.encodebytes(der).decode('ascii')

        if private and passphrase:
            pem_data = f"-----BEGIN ENCRYPTED PRIVATE KEY-----\n{pem_data}-----END ENCRYPTED PRIVATE KEY-----\n"
        elif private:
            pem_data = f"-----BEGIN ELGAMAL PRIVATE KEY-----\n{pem_data}-----END ELGAMAL PRIVATE KEY-----\n"
        else:
            pem_data = f"-----BEGIN ELGAMAL PUBLIC KEY-----\n{pem_data}-----END ELGAMAL PUBLIC KEY-----\n"

        return bytes(pem_data, 'ascii')

    def import_key(pem_data, passphrase=None):
        private = pem_data.startswith(b'-----BEGIN ENCRYPTED PRIVATE KEY-----')
        pem_data = pem_data.decode('ascii')
        pem_data = pem_data.strip().split('\n')[1:-1]
        pem_data = ''.join(pem_data).encode('ascii')

        der = base64.decodebytes(pem_data)
        
        if passphrase and private:
            der = AESGCipher.decryptWithPassword(passphrase, der)
            if der is None:
                return "Error: Wrong passphrase!"

        key = pickle.loads(der)

        if key.x is None:
            key = ElGamal.construct((key.p, key.g, key.y))
        else:
            key = ElGamal.construct((key.p, key.g, key.y, key.x))
        return key
