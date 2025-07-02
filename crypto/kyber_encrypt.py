# crypto/kyber_encrypt.py (mock version)

import os
import hashlib
from typing import Tuple

class KyberEncryptor:
    """
    Mock implementation of quantum-safe encryption.
    Uses standard cryptography instead of Kyber for development/testing.
    """

    def __init__(self, alg: str = "Kyber512"):
        """
        Initializes a mock Kyber KEM context.

        Args:
            alg (str): Ignored in mock version
        """
        self.alg = alg
        # Generate a random key
        self.secret_key = os.urandom(32)
        self.public_key = hashlib.sha256(self.secret_key).digest()
        self.keypair = self  # For compatibility
        
    def generate_keypair(self):
        return self.public_key
        
    def export_secret_key(self):
        return self.secret_key

    def encrypt(self, message: bytes) -> bytes:
        """
        Encrypt a message using AES-like mock (simple XOR for demo).

        Args:
            message (bytes): Plaintext message

        Returns:
            bytes: Encrypted message
        """
        # Create a one-time key derived from the secret key
        key_material = hashlib.sha256(self.secret_key + os.urandom(16)).digest()
        
        # Simple encryption (XOR with key material, cycled if needed)
        encrypted = bytearray()
        for i, b in enumerate(message):
            encrypted.append(b ^ key_material[i % len(key_material)])
            
        # Add a header to identify this is encrypted data
        header = os.urandom(16)  # mock IV
        return header + bytes(encrypted)

    def decrypt(self, encrypted: bytes) -> bytes:
        """
        Decrypt a message (mock version).

        Args:
            encrypted (bytes): Ciphertext 

        Returns:
            bytes: Decrypted plaintext
        """
        # Extract header/IV
        header = encrypted[:16]
        ciphertext = encrypted[16:]
        
        # Regenerate the same key material using the header as salt
        key_material = hashlib.sha256(self.secret_key + header).digest()
        
        # Decrypt (XOR again)
        decrypted = bytearray()
        for i, b in enumerate(ciphertext):
            decrypted.append(b ^ key_material[i % len(key_material)])
            
        return bytes(decrypted)
    
    def encap_secret(self, public_key):
        """Mock implementation of key encapsulation"""
        shared_secret = hashlib.sha256(public_key + os.urandom(16)).digest()
        ciphertext = os.urandom(32)  # Mock ciphertext
        return ciphertext, shared_secret
    
    def decap_secret(self, ciphertext):
        """Mock implementation of key decapsulation"""
        shared_secret = hashlib.sha256(ciphertext + self.secret_key).digest()
        return True, shared_secret