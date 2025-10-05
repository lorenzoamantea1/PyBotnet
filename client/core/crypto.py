import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend

#  Crypto Class 
class Crypto:
    def __init__(self):
        self.backend = default_backend()  # Backend for cryptography operations

    #  RSA Key Generation 
    def generate_rsa_keys(self, key_size=2048):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        public_key = private_key.public_key()
        return private_key, public_key

    #  Serialize keys 
    def serialize_private_key(self, private_key):
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    def serialize_public_key(self, public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    #  Load keys from PEM 
    def load_private_key(self, pem_data):
        return serialization.load_pem_private_key(pem_data, password=None)

    def load_public_key(self, pem_data):
        return serialization.load_pem_public_key(pem_data)
        
    #  Sign and Verify 
    def sign(self, private_key, message):
        return private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), 
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    #  RSA Encryption / Decryption 
    def rsa_encrypt(self, public_key, message: bytes) -> bytes:
        return public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def rsa_decrypt(self, private_key, ciphertext: bytes) -> bytes:
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    #  AES Symmetric Encryption 
    def generate_aes_key(self, length=32):
        return os.urandom(length)  # Generate random AES key

    def aes_encrypt(self, key: bytes, plaintext: bytes):
        iv = os.urandom(16)  # Random IV for CBC mode
        padder = sym_padding.PKCS7(128).padder()  # Pad plaintext to block size
        padded_data = padder.update(plaintext) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ciphertext  # Return IV + ciphertext

    def aes_decrypt(self, key: bytes, data: bytes):
        iv = data[:16]  # Extract IV
        ciphertext = data[16:]  # Extract ciphertext
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext
