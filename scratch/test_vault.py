import sys
import os
import unittest
from unittest.mock import patch, MagicMock

# Add backend directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from security.vault import VaultSecretsClient

class TestVaultSecretsClient(unittest.TestCase):

    @patch('security.vault.DEV_MODE', True)
    def test_dev_mode_fallback(self):
        """Test that client falls back directly to env vars in DEV_MODE."""
        with patch.dict(os.environ, {
            "POSTGRES_HOST": "dev-host",
            "POSTGRES_PASSWORD": "dev-password"
        }):
            client = VaultSecretsClient()
            self.assertIsNone(client.client)
            
            db_creds = client.get_database_credentials()
            self.assertEqual(db_creds["host"], "dev-host")
            self.assertEqual(db_creds["password"], "dev-password")

    @patch('security.vault.DEV_MODE', False)
    @patch('security.vault.VAULT_TOKEN', 'test-token')
    @patch('hvac.Client')
    def test_vault_success(self, mock_hvac_client):
        """Test successful reading from Vault."""
        mock_instance = MagicMock()
        mock_instance.is_authenticated.return_value = True
        
        # Mock KV read response
        mock_instance.secrets.kv.v2.read_secret_version.return_value = {
            "data": {
                "data": {
                    "api_key": "vault-gemini-key"
                }
            }
        }
        mock_hvac_client.return_value = mock_instance
        
        client = VaultSecretsClient()
        self.assertIsNotNone(client.client)
        
        api_key = client.get_gemini_api_key()
        self.assertEqual(api_key, "vault-gemini-key")
        mock_instance.secrets.kv.v2.read_secret_version.assert_called_with(
            path="edysor/gemini",
            mount_point="secret"
        )

    @patch('security.vault.DEV_MODE', False)
    @patch('security.vault.VAULT_TOKEN', 'test-token')
    @patch('hvac.Client')
    def test_vault_unauthenticated_fallback(self, mock_hvac_client):
        """Test that unauthenticated client falls back to environment."""
        mock_instance = MagicMock()
        mock_instance.is_authenticated.return_value = False
        mock_hvac_client.return_value = mock_instance
        
        with patch.dict(os.environ, {"GEMINI_API_KEY": "env-gemini-key"}):
            client = VaultSecretsClient()
            self.assertIsNone(client.client)
            
            api_key = client.get_gemini_api_key()
            self.assertEqual(api_key, "env-gemini-key")

    @patch('security.vault.DEV_MODE', False)
    @patch('security.vault.VAULT_TOKEN', 'test-token')
    @patch('hvac.Client')
    def test_vault_exception_fallback(self, mock_hvac_client):
        """Test that Vault exceptions trigger environment fallbacks gracefully."""
        mock_instance = MagicMock()
        mock_instance.is_authenticated.return_value = True
        mock_instance.secrets.kv.v2.read_secret_version.side_effect = Exception("Vault Down")
        mock_hvac_client.return_value = mock_instance
        
        with patch.dict(os.environ, {"POSTGRES_HOST": "fallback-db-host"}):
            client = VaultSecretsClient()
            db_creds = client.get_database_credentials()
            self.assertEqual(db_creds["host"], "fallback-db-host")

if __name__ == "__main__":
    unittest.main()
