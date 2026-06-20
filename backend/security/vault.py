import logging
import os
import hvac

logger = logging.getLogger(__name__)

# Vault environment settings
VAULT_URL = os.environ.get("VAULT_ADDR", "http://localhost:8200")
VAULT_TOKEN = os.environ.get("VAULT_TOKEN", "")
VAULT_ROLE = os.environ.get("VAULT_ROLE", "edysor-role")
DEV_MODE = os.environ.get("DEV_MODE", "true").lower() == "true"

class VaultSecretsClient:
    """A client to fetch and manage secrets from HashiCorp Vault with graceful environment fallbacks."""
    
    def __init__(self):
        self.client = None
        if DEV_MODE:
            logger.info("[Vault] Running in DEV_MODE. Vault client will not be initialized; using env fallbacks.")
            return

        if not VAULT_TOKEN:
            logger.warning("[Vault] VAULT_TOKEN environment variable not set. Falling back to env variables.")
            return

        try:
            self.client = hvac.Client(url=VAULT_URL, token=VAULT_TOKEN)
            if not self.client.is_authenticated():
                logger.error("[Vault] Authentication failed. Client is not authenticated.")
                self.client = None
            else:
                logger.info(f"[Vault] Successfully connected to Vault at {VAULT_URL}")
        except Exception as e:
            logger.error(f"[Vault] Failed to initialize hvac client: {e}. Falling back to env variables.")
            self.client = None

    def get_secret(self, path: str, mount_point: str = "secret") -> dict:
        """Reads secrets from Vault's KV v2 store. Falls back to environment variables on failure."""
        if not self.client:
            # Fallback to reading from local environment variables
            logger.debug(f"[Vault] Fetching path '{path}' from environment variables.")
            return self._get_env_fallback(path)
        
        try:
            # path is e.g. "edysor/database"
            response = self.client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point=mount_point
            )
            data = response.get("data", {}).get("data", {})
            return data
        except Exception as e:
            logger.warning(f"[Vault] Failed to read secret from Vault at '{path}': {e}. Falling back to env.")
            return self._get_env_fallback(path)

    def _get_env_fallback(self, path: str) -> dict:
        """Fallback implementation converting path keys into env lookup dicts."""
        # e.g., "edysor/database" -> POSTGRES_PASSWORD, etc.
        path_lower = path.lower()
        if "database" in path_lower or "db" in path_lower:
            return {
                "host": os.environ.get("POSTGRES_HOST", "localhost"),
                "port": os.environ.get("POSTGRES_PORT", "5432"),
                "database": os.environ.get("POSTGRES_DB", "soc"),
                "username": os.environ.get("POSTGRES_USER", "soc"),
                "password": os.environ.get("POSTGRES_PASSWORD", "changeme")
            }
        elif "gemini" in path_lower or "llm" in path_lower:
            return {
                "api_key": os.environ.get("GEMINI_API_KEY", "")
            }
        elif "encryption" in path_lower:
            return {
                "key": os.environ.get("DB_ENCRYPTION_KEY", "")
            }
        return {}

    def get_database_credentials(self) -> dict:
        """Fetches Postgres connection parameters."""
        return self.get_secret("edysor/database")

    def get_gemini_api_key(self) -> str:
        """Fetches Gemini API key."""
        secrets = self.get_secret("edysor/gemini")
        return secrets.get("api_key", "")
