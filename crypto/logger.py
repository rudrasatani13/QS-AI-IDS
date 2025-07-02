# crypto/logger.py

import os
import json
import datetime
from typing import Dict
from crypto.kyber_encrypt import KyberEncryptor
from crypto.dilithium_sign import DilithiumSigner

# Add mock AES-GCM class for compatibility
class AesGcmCipher:
    """Mock AES GCM cipher for compatibility"""
    
    class AesGcm:
        def __init__(self, key):
            self.key = key
            
        def encrypt(self, nonce, plaintext, aad):
            # Simple XOR encryption for mock
            key_material = self.key + nonce
            result = bytearray()
            for i, b in enumerate(plaintext):
                result.append(b ^ key_material[i % len(key_material)])
            return bytes(result)
            
        def decrypt(self, nonce, ciphertext, aad):
            # Same XOR operation decrypts
            key_material = self.key + nonce
            result = bytearray()
            for i, b in enumerate(ciphertext):
                result.append(b ^ key_material[i % len(key_material)])
            return bytes(result)

# Add this mock to the oqs module
import sys
import types

# Create a mock oqs module if it doesn't exist
if 'oqs' not in sys.modules:
    oqs_module = types.ModuleType('oqs')
    oqs_module.KeyEncapsulation = KyberEncryptor
    oqs_module.Signature = DilithiumSigner
    oqs_module.AesGcmCipher = AesGcmCipher
    sys.modules['oqs'] = oqs_module


class SecureLogger:
    """
    Quantum-safe encrypted and signed logging system for network activity and anomalies.
    """

    def __init__(self, log_dir: str = "secure_logs"):
        """
        Args:
            log_dir (str): Directory to store encrypted and signed logs
        """
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)

        self.kyber = KyberEncryptor()
        self.signer = DilithiumSigner()

    def log_event(self, entry: Dict):
        """
        Logs an event securely.

        Args:
            entry (dict): Log entry containing timestamp, anomaly score, features, etc.
        """
        timestamp = datetime.datetime.utcnow().isoformat()
        log_entry = {
            "timestamp": timestamp,
            "entry": entry
        }

        plaintext = json.dumps(log_entry, indent=2).encode("utf-8")
        encrypted = self.kyber.encrypt(plaintext)
        signature = self.signer.sign(encrypted)

        filename = f"log_{timestamp.replace(':', '_')}.json"

        with open(os.path.join(self.log_dir, filename), "wb") as f:
            f.write(signature + b"||" + encrypted)

        print(f"[LOGGER] Secure log saved: {filename}")

    def verify_log(self, log_path: str) -> bool:
        """
        Verifies the integrity and authenticity of a log file.

        Args:
            log_path (str): Path to encrypted log file

        Returns:
            bool: True if signature is valid, False otherwise
        """
        with open(log_path, "rb") as f:
            content = f.read()

        try:
            signature, encrypted = content.split(b"||", 1)
        except ValueError:
            return False

        return self.signer.verify(encrypted, signature)