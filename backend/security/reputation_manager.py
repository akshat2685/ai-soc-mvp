import logging
from database import get_db

logger = logging.getLogger(__name__)

# Initialize local schema tracking
def init_reputation_schema():
    query = """
    CREATE TABLE IF NOT EXISTS agent_reputations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_name TEXT UNIQUE NOT NULL,
        reputation_score REAL DEFAULT 1.0,
        anomalies_count INTEGER DEFAULT 0,
        last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """
    with get_db() as conn:
        try:
            conn.execute(query)
            conn.commit()
        except Exception as e:
            logger.error(f"[Reputation DB] Init table failed: {e}")

class AgentReputationManager:
    @staticmethod
    def get_agent_reputation(agent_name: str) -> float:
        init_reputation_schema()
        try:
            with get_db() as conn:
                cur = conn.execute("SELECT reputation_score FROM agent_reputations WHERE agent_name = ?", (agent_name,))
                row = cur.fetchone()
                if row:
                    return float(row["reputation_score"])
        except Exception as e:
            logger.error(f"[Reputation Manager] Failed to retrieve reputation: {e}")
        return 1.0

    @staticmethod
    def record_anomaly(agent_name: str, score_penalty: float = 0.15):
        """Reduces agent reputation dynamically in DB if suspicious behavior is logged."""
        init_reputation_schema()
        try:
            with get_db() as conn:
                # Upsert query translation will handleSQLite vs PG
                cur = conn.execute("SELECT id, reputation_score, anomalies_count FROM agent_reputations WHERE agent_name = ?", (agent_name,))
                row = cur.fetchone()
                if row:
                    new_score = max(0.0, float(row["reputation_score"]) - score_penalty)
                    new_anoms = int(row["anomalies_count"]) + 1
                    conn.execute(
                        "UPDATE agent_reputations SET reputation_score = ?, anomalies_count = ?, last_updated = datetime('now') WHERE agent_name = ?",
                        (new_score, new_anoms, agent_name)
                    )
                else:
                    new_score = max(0.0, 1.0 - score_penalty)
                    conn.execute(
                        "INSERT INTO agent_reputations (agent_name, reputation_score, anomalies_count) VALUES (?, ?, 1)",
                        (agent_name, new_score)
                    )
                conn.commit()
                logger.warning(f"[Reputation Manager] Logged anomaly for '{agent_name}'. Reputation: {new_score}")
        except Exception as e:
            logger.error(f"[Reputation Manager] Write failed: {e}")
