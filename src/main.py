from Key import PublicKeyWrapper, PrivateKeyWrapper
from AsymmetricCipher import *
from datetime import datetime
from Crypto.PublicKey import RSA, ElGamal, DSA
from hash import SHA1Wrapper
from Keyring import Keyring


def main():
    timestamp = datetime.now()
    rsa_key = RSA.generate(1024)
    key = PrivateKeyWrapper(timestamp, rsa_key, "Peter", "example@example.com", RSACipher(), b"peter123")

	# Encrypt and Decrypt
    Message = b"Hello World"
    encrypted = key.encrypt(Message)

    print("\n\n")
    print(encrypted)
    print("\n\n")
    print(key.decrypt(encrypted, b'peter123'))


	# Sign and Verify
    sha = SHA1Wrapper()
    hash = sha.getHash(Message)
    signature = key.sign(hash, b'peter123')

    print(signature)
    hash2 = sha.getHash(b"test")
    print(key.verify(hash2, signature))
    print(key.verify(hash, signature))


if __name__ == "__main__":
    main()
