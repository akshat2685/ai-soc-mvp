import json
import logging
from database import get_db

logger = logging.getLogger(__name__)

def init_soar_tables():
    """Create SOAR tables in the relational database if they do not exist."""
    queries = [
        """
        CREATE TABLE IF NOT EXISTS soar_integration_configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT DEFAULT 'default',
            integration_name TEXT NOT NULL,
            config_data TEXT NOT NULL,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(tenant_id, integration_name)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS soar_playbook_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT DEFAULT 'default',
            playbook_name TEXT NOT NULL,
            incident_id INTEGER,
            target TEXT,
            status TEXT DEFAULT 'PENDING',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS soar_action_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            playbook_run_id INTEGER NOT NULL,
            action_name TEXT NOT NULL,
            integration_name TEXT NOT NULL,
            status TEXT DEFAULT 'PENDING',
            attempt_count INTEGER DEFAULT 0,
            max_retries INTEGER DEFAULT 3,
            error_message TEXT,
            response_data TEXT,
            rollback_data TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS soar_approvals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT DEFAULT 'default',
            playbook_run_id INTEGER,
            action_name TEXT NOT NULL,
            target TEXT,
            status TEXT DEFAULT 'PENDING',
            evidence TEXT,
            requested_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            reviewed_by TEXT,
            reviewed_at DATETIME
        )
        """
    ]

    with get_db() as conn:
        for q in queries:
            try:
                conn.execute(q)
                conn.commit()
            except Exception as e:
                logger.error(f"[SOAR Config] Failed to create table query: {e}")

def get_integration_config(tenant_id: str, integration_name: str) -> dict:
    """Retrieve integration configuration for a tenant, falling back to 'default' or an empty dict."""
    init_soar_tables()
    from security.encryption import EncryptionManager
    cipher = EncryptionManager()
    
    with get_db() as conn:
        # Check tenant specific config
        cur = conn.execute(
            "SELECT config_data FROM soar_integration_configs WHERE tenant_id = ? AND integration_name = ?",
            (tenant_id, integration_name)
        )
        row = cur.fetchone()
        if row:
            val = row[0]
            try:
                # Attempt decryption first
                decrypted = cipher.decrypt(val)
                return json.loads(decrypted or "{}")
            except Exception:
                # Fallback to reading raw JSON if not encrypted
                try:
                    return json.loads(val or "{}")
                except Exception:
                    return {}

        # Fallback to default
        if tenant_id != 'default':
            cur = conn.execute(
                "SELECT config_data FROM soar_integration_configs WHERE tenant_id = 'default' AND integration_name = ?",
                (integration_name,)
            )
            row = cur.fetchone()
            if row:
                val = row[0]
                try:
                    decrypted = cipher.decrypt(val)
                    return json.loads(decrypted or "{}")
                except Exception:
                    try:
                        return json.loads(val or "{}")
                    except Exception:
                        return {}

    return {}

def save_integration_config(tenant_id: str, integration_name: str, config_data: dict):
    """Save or update integration configuration for a tenant."""
    init_soar_tables()
    from security.encryption import EncryptionManager
    cipher = EncryptionManager()
    
    config_str = json.dumps(config_data)
    encrypted_config = cipher.encrypt(config_str)
    
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO soar_integration_configs (tenant_id, integration_name, config_data, updated_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(tenant_id, integration_name) DO UPDATE SET
                config_data = excluded.config_data,
                updated_at = CURRENT_TIMESTAMP
            """,
            (tenant_id, integration_name, encrypted_config)
        )
        conn.commit()

