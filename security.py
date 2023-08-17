from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class Security():
    def __init__(self, save_keys=False):
        self.private_key = None
        self.public_key = None

        private_key, public_key = self.load_rsa_keys()
        if all((private_key, public_key)):
            self.generate_rsa_keys(save=save_keys)

    def generate_rsa_keys(self, save=False):
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.publickey()
        if save:
            with open("./private.pem", "wb") as f:
                f.write(self.private_key.exportKey())
            with open("./public.pem", "wb") as f:
                f.write(self.public_key.exportKey())
        return self.private_key, self.public_key

    def load_rsa_keys(self):
        try:
            self.private_key = RSA.import_key(open("./private.pem").read())
        except FileNotFoundError:
            self.private_key = None
        try:
            self.public_key = RSA.import_key(open("./public.pem").read())
        except FileNotFoundError:
            self.private_key = None
        return self.private_key, self.public_key

    def encrypt_rsa(self, payload: bytes, key=None):
        if not key:
            key = self.private_key
        cipher = PKCS1_OAEP.new(key)
        return cipher.encrypt(payload)
    
    def decrypt_rsa(self, payload: bytes, key=None):
        if not key:
            key = self.public_key
        cipher = PKCS1_OAEP.new(key)
        return cipher.decrypt(payload)

    def export_key(self, key=None, passphrase: bytes=None):
        if not key:
            key = self.public_key
        return key.exportKey(passphrase=passphrase, pkcs=8, protection="scryptAndAES128-CBC")

    def import_key(self, key, passphrase: bytes=None):
        return RSA.import_key(key, passphrase=passphrase)
    
    def generate_aes_key(self):
        key = get_random_bytes(16)
        nonce = get_random_bytes(16)
        return key, nonce
    
    def encrypt_aes(self, key, nonce, payload):
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        return cipher.encrypt_and_digest(payload)

    def decrypt_aes(self, key, nonce, ciphertext, tag=None):
        cipher_aes = AES.new(key, AES.MODE_EAX, nonce)
        if tag:
            data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        else:
            data = cipher_aes.decrypt(ciphertext)
        return data

    def sha_256(self, data: bytes):
        hashObject = SHA256.new(data=data)
        return hashObject.digest()
