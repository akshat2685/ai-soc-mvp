import sqlite3
import os
from contextlib import contextmanager

DB_PATH = os.path.join(os.path.dirname(__file__), "soc.db")

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                event_type TEXT,
                source_ip TEXT,
                user_id TEXT,
                status TEXT,
                device_id TEXT,
                user_agent TEXT,
                endpoint TEXT,
                method TEXT,
                device_fingerprint TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                title TEXT,
                severity TEXT,
                confidence TEXT DEFAULT 'HIGH',
                attack_type TEXT,
                evidence TEXT,
                attacker_ip TEXT,
                llm_summary TEXT,
                attacker_report TEXT,
                verdict TEXT DEFAULT 'PENDING',
                incident_id INTEGER,
                device_fingerprint TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                title TEXT,
                severity TEXT,
                status TEXT DEFAULT 'ACTIVE',
                correlation_key TEXT,
                llm_summary TEXT,
                verdict TEXT DEFAULT 'PENDING'
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS responses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                action_type TEXT,
                target TEXT,
                details TEXT,
                alert_id INTEGER,
                incident_id INTEGER
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS threat_intel (
                ip TEXT PRIMARY KEY,
                country TEXT,
                country_code TEXT,
                flag TEXT,
                isp TEXT,
                abuse_score INTEGER,
                usage_type TEXT,
                source TEXT,
                last_checked DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Safe migrations for existing DBs
        try:
            conn.execute("ALTER TABLE logs ADD COLUMN device_fingerprint TEXT")
        except sqlite3.OperationalError:
            pass # column already exists
            
        try:
            conn.execute("ALTER TABLE alerts ADD COLUMN incident_id INTEGER")
        except sqlite3.OperationalError:
            pass
            
        try:
            conn.execute("ALTER TABLE alerts ADD COLUMN device_fingerprint TEXT")
        except sqlite3.OperationalError:
            pass

        try:
            conn.execute("ALTER TABLE responses ADD COLUMN incident_id INTEGER")
        except sqlite3.OperationalError:
            pass

        conn.commit()

@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()
