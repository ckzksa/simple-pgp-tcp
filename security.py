from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def generate_rsa_keys(save=False):
    private_key = RSA.generate(2048)
    public_key = private_key.publickey()
    if save:
        with open("./private.pem", "wb") as f:
            f.write(private_key.exportKey())
        with open("./public.pem", "wb") as f:
            f.write(public_key.exportKey())
    return private_key, public_key

def load_rsa_keys():
    try:
        private_key = RSA.import_key(open("./private.pem").read())
        public_key = RSA.import_key(open("./public.pem").read())
    except FileNotFoundError:
        return None, None
        
    return private_key, public_key

def encrypt_rsa(message: bytes, key):
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(message)

def decrypt_rsa(message: bytes, key):
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(message)

def export_key(key, passphrase: bytes=None):
    return key.exportKey(passphrase=passphrase, pkcs=8, protection="scryptAndAES128-CBC")

def import_key(key, passphrase: bytes=None):
    return RSA.import_key(key, passphrase=passphrase)

def rsa_sign(key, message):
    hash = SHA256.new(message)
    signature = pkcs1_15.new(key).sign(hash)
    return signature

def rsa_verify(key, message, signature):
    hash = SHA256.new(message)
    try:
        pkcs1_15.new(key).verify(hash, signature)
        return True
    except (ValueError):
        return False

def generate_aes_key():
    key = get_random_bytes(16)
    nonce = get_random_bytes(16)
    return key, nonce

def encrypt_aes(key, nonce, data):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.encrypt_and_digest(data)

def decrypt_aes(key, nonce, ciphertext, tag=None):
    cipher_aes = AES.new(key, AES.MODE_EAX, nonce)
    if tag:
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    else:
        data = cipher_aes.decrypt(ciphertext)
    return data

def sha_256(data: bytes):
    hashObject = SHA256.new(data=data)
    return hashObject.digest()
