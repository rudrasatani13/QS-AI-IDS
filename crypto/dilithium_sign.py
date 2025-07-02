# crypto/dilithium_sign.py (mock version)

import hmac
import hashlib
import os

class DilithiumSigner:
    """
    Mock implementation of quantum-safe signing.
    Uses HMAC-SHA256 instead of Dilithium for development/testing.
    """

    def __init__(self, alg: str = "Dilithium2"):
        """
        Initialize mock Dilithium signature scheme.

        Args:
            alg (str): Ignored in mock version
        """
        self.alg = alg
        self.secret_key = os.urandom(32)
        self.public_key = hashlib.sha256(self.secret_key).digest()
        self.sig = self  # For compatibility

    def generate_keypair(self):
        return self.public_key
        
    def export_secret_key(self):
        return self.secret_key

    def sign(self, message: bytes) -> bytes:
        """
        Sign the message using HMAC-SHA256.

        Args:
            message (bytes): Raw message

        Returns:
            bytes: Signature
        """
        return hmac.new(self.secret_key, message, hashlib.sha256).digest()

    def verify(self, message: bytes, signature: bytes, public_key=None) -> bool:
        """
        Verify a signature.

        Args:
            message (bytes): Original signed message
            signature (bytes): Signature to verify
            public_key: Optional public key (used if provided)

        Returns:
            bool: True if signature is valid
        """
        expected = hmac.new(self.secret_key, message, hashlib.sha256).digest()
        return hmac.compare_digest(signature, expected)
        
    def import_secret_key(self, secret_key):
        """Mock implementation for compatibility"""
        self.secret_key = secret_key