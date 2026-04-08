from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

class CryptoManager:
    @staticmethod
    def generate_key_pair():
        """Generate X25519 key pair."""
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def derive_shared_key(private_key, peer_public_key):
        """Derive a shared key using X25519."""
        shared_key = private_key.exchange(peer_public_key)
        # Use HKDF to derive a symmetric key
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data'
        ).derive(shared_key)
        return derived_key

    @staticmethod
    def encrypt_message(key, plaintext):
        """Encrypt a message using AES-GCM."""
        iv = os.urandom(12)  # Generate a random IV
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return iv, ciphertext, encryptor.tag

    @staticmethod
    def decrypt_message(key, iv, ciphertext, tag):
        """Decrypt a message using AES-GCM."""
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext