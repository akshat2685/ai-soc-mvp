import sys
import os
import unittest

# Add backend directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from security.encryption import EncryptionManager

class TestEncryptionManager(unittest.TestCase):

    def test_encrypt_decrypt_roundtrip(self):
        """Test encryption and decryption of standard strings."""
        manager = EncryptionManager("test-master-key")
        secret_text = "super_secret_api_key_12345!"
        
        ciphertext = manager.encrypt(secret_text)
        self.assertNotEqual(ciphertext, secret_text)
        
        plaintext = manager.decrypt(ciphertext)
        self.assertEqual(plaintext, secret_text)

    def test_different_keys_fail_to_decrypt(self):
        """Test that different keys cannot decrypt each other's ciphertext."""
        manager1 = EncryptionManager("key-alpha")
        manager2 = EncryptionManager("key-beta")
        secret_text = "secure-data"
        
        ciphertext = manager1.encrypt(secret_text)
        
        with self.assertRaises(ValueError):
            manager2.decrypt(ciphertext)

    def test_handle_none(self):
        """Test that None values are returned as None."""
        manager = EncryptionManager()
        self.assertIsNone(manager.encrypt(None))
        self.assertIsNone(manager.decrypt(None))

    def test_corrupted_data_raises_error(self):
        """Test that corrupted ciphertexts raise ValueError."""
        manager = EncryptionManager()
        with self.assertRaises(ValueError):
            manager.decrypt("invalid-ciphertext-string")

if __name__ == "__main__":
    unittest.main()
