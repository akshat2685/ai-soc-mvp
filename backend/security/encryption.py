import base64
import logging
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)

# Fallback development key (WARNING: Not for production use)
DEFAULT_DEV_KEY = "dev-secret-key-change-in-production-12345!"

class EncryptionManager:
    """Handles encryption and decryption of sensitive database fields and integration secrets."""
    
    def __init__(self, master_key: str = None):
        if not master_key:
            master_key = os.environ.get("DB_ENCRYPTION_KEY", DEFAULT_DEV_KEY)
            if master_key == DEFAULT_DEV_KEY:
                logger.warning(
                    "[Security] Using DEFAULT_DEV_KEY for encryption. "
                    "Please set DB_ENCRYPTION_KEY environment variable in production."
                )
        
        # Derive a cryptographically strong 32-byte key for Fernet using PBKDF2HMAC
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"edysor-soc-salt-2026",
            iterations=100000,
        )
        derived_key = kdf.derive(master_key.encode())
        fernet_key = base64.urlsafe_b64encode(derived_key)
        self.cipher = Fernet(fernet_key)

    def encrypt(self, plaintext: str) -> str:
        """Encrypts a plaintext string and returns a base64 encoded ciphertext string."""
        if plaintext is None:
            return None
        if not isinstance(plaintext, str):
            plaintext = str(plaintext)
        encrypted_bytes = self.cipher.encrypt(plaintext.encode())
        return encrypted_bytes.decode()

    def decrypt(self, ciphertext: str) -> str:
        """Decrypts a base64 encoded ciphertext string back to plaintext."""
        if ciphertext is None:
            return None
        try:
            decrypted_bytes = self.cipher.decrypt(ciphertext.encode())
            return decrypted_bytes.decode()
        except Exception as e:
            logger.error(f"[Security] Decryption failed: {e}")
            raise ValueError("Decryption failed: Invalid key or corrupted data.") from e
