"""Unified Database Client supporting PostgreSQL, ClickHouse, and local SQLite fallback."""
import os
import re
import logging
import sqlite3
from contextlib import contextmanager

logger = logging.getLogger(__name__)

DB_TYPE = os.environ.get("DB_TYPE", "sqlite")

# PostgreSQL Config
POSTGRES_HOST = os.environ.get("POSTGRES_HOST", "localhost")
POSTGRES_PORT = int(os.environ.get("POSTGRES_PORT", 5432))
POSTGRES_DB = os.environ.get("POSTGRES_DB", "soc")
POSTGRES_USER = os.environ.get("POSTGRES_USER", "soc")
POSTGRES_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "changeme")

DB_PATH = os.path.join(os.path.dirname(__file__), "soc.db")

_pg_pool = None

def get_postgres_connection():
    global _pg_pool
    if DB_TYPE != "postgres":
        return None
    
    try:
        import psycopg2
        from psycopg2 import pool
        if _pg_pool is None:
            _pg_pool = psycopg2.pool.SimpleConnectionPool(
                1, 20,
                host=POSTGRES_HOST,
                port=POSTGRES_PORT,
                database=POSTGRES_DB,
                user=POSTGRES_USER,
                password=POSTGRES_PASSWORD
            )
        return _pg_pool.getconn()
    except Exception as e:
        logger.warning(f"Failed to connect to PostgreSQL ({POSTGRES_HOST}:{POSTGRES_PORT}): {e}. Falling back to SQLite.")
        return None

def release_postgres_connection(conn):
    global _pg_pool
    if _pg_pool and conn:
        try:
            _pg_pool.putconn(conn)
        except Exception:
            pass

def translate_query(sql: str, db_type: str = "postgres") -> str:
    """Translate SQLite-dialect SQL statements to target database dialects."""
    if db_type == "postgres":
        # 1. ? -> %s
        sql = sql.replace("?", "%s")
        # 2. AUTOINCREMENT -> SERIAL
        sql = re.sub(r"INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT", "SERIAL PRIMARY KEY", sql, flags=re.IGNORECASE)
        # 4. datetime('now') -> CURRENT_TIMESTAMP
        sql = re.sub(r"datetime\('now'\)", "CURRENT_TIMESTAMP", sql, flags=re.IGNORECASE)
        # 5. datetime('now', '-30 minutes') -> NOW() - INTERVAL '30 minutes'
        sql = re.sub(r"datetime\('now',\s*'-(?P<val>\d+)\s+(?P<unit>\w+)'\)", r"NOW() - INTERVAL '\g<val> \g<unit>'", sql, flags=re.IGNORECASE)
        # 6. datetime('now', ? || ' minutes') -> NOW() - (INTERVAL '1 minute' * %s)
        sql = re.sub(r"datetime\('now',\s*%s\s*\|\|\s*' minutes'\)", r"NOW() - (INTERVAL '1 minute' * %s)", sql, flags=re.IGNORECASE)
        sql = re.sub(r"datetime\('now',\s*\?\s*\|\|\s*' minutes'\)", r"NOW() - (INTERVAL '1 minute' * %s)", sql, flags=re.IGNORECASE)
        # 7. strftime('%Y-%m-%d %H', timestamp) -> TO_CHAR(timestamp, 'YYYY-MM-DD HH24')
        sql = re.sub(r"strftime\('%Y-%m-%d %H',\s*timestamp\)", "TO_CHAR(timestamp, 'YYYY-MM-DD HH24')", sql, flags=re.IGNORECASE)
        # 3. DATETIME type -> TIMESTAMP
        sql = re.sub(r"\bDATETIME\b", "TIMESTAMP", sql, flags=re.IGNORECASE)
        # 8. julianday calculations
        sql = re.sub(
            r"julianday\(resolved_at\)\s*-\s*julianday\(timestamp\)",
            "EXTRACT(EPOCH FROM (resolved_at - timestamp)) / 86400.0",
            sql, flags=re.IGNORECASE
        )
        sql = re.sub(
            r"julianday\(a\.timestamp\)\s*-\s*julianday\(l\.min_ts\)",
            "EXTRACT(EPOCH FROM (a.timestamp - l.min_ts)) / 86400.0",
            sql, flags=re.IGNORECASE
        )
    elif db_type == "clickhouse":
        # 1. ? -> %s
        sql = sql.replace("?", "%s")
        # 2. datetime('now', '-5 minutes') -> now() - INTERVAL 5 MINUTE
        sql = re.sub(r"datetime\('now',\s*'-(?P<val>\d+)\s+(?P<unit>\w+)'\)", r"now() - INTERVAL \g<val> \g<unit>", sql, flags=re.IGNORECASE)
        # 3. datetime('now') -> now()
        sql = re.sub(r"datetime\('now'\)", "now()", sql, flags=re.IGNORECASE)
        # 4. strftime('%Y-%m-%d %H', timestamp) -> formatDateTime(timestamp, '%Y-%m-%d %H')
        sql = re.sub(r"strftime\('%Y-%m-%d %H',\s*timestamp\)", "formatDateTime(timestamp, '%Y-%m-%d %H')", sql, flags=re.IGNORECASE)
    return sql

class UnifiedRow:
    """Wrapper that mimics sqlite3.Row for dict & tuple index compatibility."""
    def __init__(self, cols, vals):
        self._cols = list(cols)
        self._vals = list(vals)
        self._dict = dict(zip(self._cols, self._vals))

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._vals[key]
        return self._dict[key]

    def keys(self):
        return self._cols

    def __iter__(self):
        return iter(self._vals)

    def __len__(self):
        return len(self._vals)

    def get(self, key, default=None):
        return self._dict.get(key, default)

    def __repr__(self):
        return str(self._dict)

class UnifiedCursor:
    def __init__(self, pg_conn=None, sl_conn=None, db_type="sqlite"):
        self.pg_conn = pg_conn
        self.sl_conn = sl_conn
        self.db_type = db_type
        
        self.pg_cur = pg_conn.cursor() if pg_conn else None
        self.sl_cur = sl_conn.cursor() if sl_conn else None
        
        self.description = None
        self.lastrowid = None
        self.active_cur = None
        self._results = []
        self._index = 0

    def execute(self, sql, params=None):
        from clickhouse_client import get_clickhouse_client, query_clickhouse
        
        is_logs_query = re.search(r"\b(FROM|JOIN|INTO|UPDATE)\s+logs\b", sql, re.IGNORECASE) is not None
        
        if is_logs_query and get_clickhouse_client():
            # ClickHouse OLAP route
            ch_sql = translate_query(sql, db_type="clickhouse")
            if params:
                formatted_params = []
                for p in params:
                    if isinstance(p, str):
                        escaped = p.replace("'", "''")
                        formatted_params.append(f"'{escaped}'")
                    elif p is None:
                        formatted_params.append("NULL")
                    else:
                        formatted_params.append(str(p))
                
                for fp in formatted_params:
                    if "?" in ch_sql:
                        ch_sql = ch_sql.replace("?", fp, 1)
                    elif "%s" in ch_sql:
                        ch_sql = ch_sql.replace("%s", fp, 1)
            
            logger.info(f"[ROUTER] OLAP ClickHouse: {ch_sql}")
            try:
                rows = query_clickhouse(ch_sql)
                self.description = [("id",), ("timestamp",), ("event_type",), ("source_ip",), ("user_id",), ("status",), ("device_id",), ("user_agent",), ("endpoint",), ("method",), ("device_fingerprint",), ("geo_country",), ("geo_asn",), ("tenant_id",)]
                cols = [d[0] for d in self.description]
                self._results = [UnifiedRow(cols, [r.get(c) for c in cols]) for r in rows]
                self._index = 0
                self.active_cur = "clickhouse"
                return self
            except Exception as e:
                logger.error(f"ClickHouse failed: {e}. Falling back to relational DB.")
                is_logs_query = False
                
        if not is_logs_query or not get_clickhouse_client():
            if self.db_type == "postgres":
                pg_sql = translate_query(sql, db_type="postgres")
                logger.info(f"[ROUTER] OLTP Postgres: {pg_sql} (params: {params})")
                
                # Check for INSERT to populate lastrowid (returning primary key id)
                if pg_sql.strip().upper().startswith("INSERT INTO") and "RETURNING" not in pg_sql.upper():
                    table_match = re.search(r"INSERT\s+INTO\s+(\w+)", pg_sql, re.IGNORECASE)
                    if table_match and table_match.group(1).lower() in (
                        "alerts", "incidents", "responses", "audit_log", "pending_approvals",
                        "email_drafts", "users", "api_keys", "virtual_patches", "vulnerabilities"
                    ):
                        pg_sql_returning = pg_sql.rstrip(";") + " RETURNING id"
                        try:
                            self.pg_cur.execute(pg_sql_returning, params or ())
                            row = self.pg_cur.fetchone()
                            if row:
                                self.lastrowid = row[0]
                            self.active_cur = "postgres"
                            return self
                        except Exception:
                            # rollback and retry without returning
                            self.pg_conn.rollback()
                
                self.pg_cur.execute(pg_sql, params or ())
                self.description = self.pg_cur.description
                self.active_cur = "postgres"
            else:
                logger.info(f"[ROUTER] OLTP SQLite: {sql}")
                self.sl_cur.execute(sql, params or ())
                self.description = self.sl_cur.description
                self.lastrowid = self.sl_cur.lastrowid
                self.active_cur = "sqlite"
        return self

    def fetchall(self):
        if self.active_cur == "clickhouse":
            return self._results
        elif self.active_cur == "postgres":
            rows = self.pg_cur.fetchall()
            cols = [desc[0] for desc in self.description] if self.description else []
            return [UnifiedRow(cols, r) for r in rows]
        elif self.active_cur == "sqlite":
            rows = self.sl_cur.fetchall()
            cols = [desc[0] for desc in self.description] if self.description else []
            return [UnifiedRow(cols, r) for r in rows]
        return []

    def fetchone(self):
        if self.active_cur == "clickhouse":
            if self._index < len(self._results):
                row = self._results[self._index]
                self._index += 1
                return row
            return None
        elif self.active_cur == "postgres":
            row = self.pg_cur.fetchone()
            if not row:
                return None
            cols = [desc[0] for desc in self.description] if self.description else []
            return UnifiedRow(cols, row)
        elif self.active_cur == "sqlite":
            row = self.sl_cur.fetchone()
            if not row:
                return None
            cols = [desc[0] for desc in self.description] if self.description else []
            return UnifiedRow(cols, row)
        return None

class UnifiedConnection:
    def __init__(self, pg_conn=None, sl_conn=None):
        self.pg_conn = pg_conn
        self.sl_conn = sl_conn
        self.db_type = "postgres" if pg_conn else "sqlite"

    def execute(self, sql, params=None):
        cur = self.cursor()
        cur.execute(sql, params)
        return cur

    def cursor(self):
        return UnifiedCursor(self.pg_conn, self.sl_conn, self.db_type)

    def commit(self):
        if self.pg_conn:
            self.pg_conn.commit()
        if self.sl_conn:
            self.sl_conn.commit()

    def rollback(self):
        if self.pg_conn:
            self.pg_conn.rollback()
        if self.sl_conn:
            self.sl_conn.rollback()

    def close(self):
        if self.pg_conn:
            release_postgres_connection(self.pg_conn)
        if self.sl_conn:
            self.sl_conn.close()

def init_db():
    """Seed the relational tables in PostgreSQL or SQLite."""
    # Run ClickHouse init
    try:
        from clickhouse_client import init_clickhouse
        init_clickhouse()
    except Exception as e:
        logger.error(f"Failed to init ClickHouse schema: {e}")

    with get_db() as conn:
        # Tables definitions (SQLite syntax, will be translated to Postgres on-the-fly)
        tables = [
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                title TEXT,
                severity TEXT,
                confidence TEXT DEFAULT 'HIGH',
                confidence_score INTEGER DEFAULT 80,
                attack_type TEXT,
                evidence TEXT,
                evidence_citations TEXT,
                attacker_ip TEXT,
                llm_summary TEXT,
                attacker_report TEXT,
                verdict TEXT DEFAULT 'PENDING',
                incident_id INTEGER,
                device_fingerprint TEXT,
                tenant_id TEXT DEFAULT 'default'
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                title TEXT,
                severity TEXT,
                status TEXT DEFAULT 'ACTIVE',
                correlation_key TEXT,
                llm_summary TEXT,
                verdict TEXT DEFAULT 'PENDING',
                analyst_notes TEXT,
                resolved_at DATETIME,
                tenant_id TEXT DEFAULT 'default'
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS responses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                action_type TEXT,
                target TEXT,
                details TEXT,
                alert_id INTEGER,
                incident_id INTEGER,
                response_tier INTEGER DEFAULT 4,
                status TEXT DEFAULT 'ACTIVE',
                expires_at DATETIME,
                approved_by TEXT,
                approval_status TEXT DEFAULT 'AUTO'
            )
            """,
            """
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
            """,
            """
            CREATE TABLE IF NOT EXISTS assets (
                ip_address TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                owner TEXT,
                os TEXT,
                criticality TEXT DEFAULT 'LOW',
                internet_facing INTEGER DEFAULT 0,
                contains_customer_data INTEGER DEFAULT 0,
                last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT,
                cve_id TEXT,
                severity TEXT,
                title TEXT,
                description TEXT,
                tool_source TEXT,
                detected_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS entity_baselines (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entity_type TEXT,
                entity_value TEXT,
                event_type TEXT,
                hour_of_day INTEGER,
                day_of_week INTEGER,
                avg_count REAL,
                std_dev REAL,
                sample_count INTEGER,
                last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(entity_type, entity_value, event_type, hour_of_day, day_of_week)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS correlation_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                attack_types TEXT,
                time_window_minutes INTEGER DEFAULT 30,
                min_alerts INTEGER DEFAULT 2,
                escalate_severity TEXT DEFAULT 'CRITICAL',
                enabled INTEGER DEFAULT 1
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS analyst_feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                alert_id INTEGER,
                incident_id INTEGER,
                analyst_id TEXT DEFAULT 'system',
                verdict TEXT,
                notes TEXT,
                attack_type TEXT,
                evidence_snapshot TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                action_type TEXT NOT NULL,
                response_tier INTEGER,
                target TEXT NOT NULL,
                alert_id INTEGER,
                incident_id INTEGER,
                evidence_snapshot TEXT,
                triggered_by TEXT DEFAULT 'SYSTEM',
                approval_status TEXT,
                approved_by TEXT,
                execution_result TEXT,
                notes TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS pending_approvals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                action_type TEXT,
                response_tier INTEGER,
                target TEXT,
                alert_id INTEGER,
                incident_id INTEGER,
                evidence_snapshot TEXT,
                status TEXT DEFAULT 'PENDING',
                reviewed_by TEXT,
                reviewed_at DATETIME
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS email_drafts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                alert_id INTEGER,
                incident_id INTEGER,
                target_ip TEXT,
                subject TEXT,
                body TEXT,
                status TEXT DEFAULT 'DRAFT',
                reviewed_by TEXT,
                sent_at DATETIME
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'analyst',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_login DATETIME,
                is_active INTEGER DEFAULT 1,
                tenant_id TEXT DEFAULT 'default'
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_value TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_used_at DATETIME,
                is_active INTEGER DEFAULT 1,
                user_id TEXT,
                tenant_id TEXT DEFAULT 'default'
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS pipeline_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo_name TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                cve_id TEXT,
                severity TEXT NOT NULL,
                description TEXT,
                commit_hash TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS virtual_patches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_name TEXT NOT NULL,
                target_endpoint TEXT NOT NULL,
                pattern_regex TEXT NOT NULL,
                action TEXT DEFAULT 'BLOCK',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS endpoint_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_name TEXT NOT NULL,
                event_id INTEGER NOT NULL,
                condition TEXT NOT NULL,
                pattern TEXT NOT NULL,
                attack_type TEXT,
                severity TEXT DEFAULT 'HIGH',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS investigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER UNIQUE,
                incident_id INTEGER,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                collected_logs TEXT,
                collected_assets TEXT,
                collected_vulnerabilities TEXT,
                collected_user_history TEXT,
                collected_previous_incidents TEXT,
                correlation_summary TEXT,
                timeline TEXT,
                confidence_score INTEGER,
                probable_root_cause TEXT,
                recommended_remediation TEXT,
                executive_summary TEXT,
                technical_summary TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS mitre_mappings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                attack_type TEXT UNIQUE NOT NULL,
                tactic_id TEXT NOT NULL,
                tactic_name TEXT NOT NULL,
                technique_id TEXT NOT NULL,
                technique_name TEXT NOT NULL,
                description TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS cisa_kev (
                cve_id TEXT PRIMARY KEY,
                vendor_project TEXT,
                product TEXT,
                vulnerability_name TEXT,
                date_added TEXT,
                short_description TEXT,
                required_action TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS cve_feed (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                cvss_score REAL,
                severity TEXT,
                published_date TEXT,
                last_modified_date TEXT
            )
            """,
            """
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
                device_fingerprint TEXT,
                geo_country TEXT,
                geo_asn TEXT,
                tenant_id TEXT DEFAULT 'default'
            )
            """
        ]

        for query in tables:
            try:
                conn.execute(query)
                conn.commit()
            except Exception as e:
                logger.error(f"Failed to create table: {e}")

        # Seed initial data if tables are empty
        try:
            cur = conn.execute("SELECT COUNT(*) as c FROM correlation_rules")
            if cur.fetchone()['c'] == 0:
                conn.execute(
                    "INSERT INTO correlation_rules (name, attack_types, time_window_minutes, min_alerts, escalate_severity) VALUES (?, ?, ?, ?, ?)",
                    ("Multi-vector attack", '["CREDENTIAL_STUFFING","ACCOUNT_TAKEOVER","BUSINESS_LOGIC"]', 30, 2, "CRITICAL")
                )
                conn.execute(
                    "INSERT INTO correlation_rules (name, attack_types, time_window_minutes, min_alerts, escalate_severity) VALUES (?, ?, ?, ?, ?)",
                    ("Credential + OTP combo", '["CREDENTIAL_STUFFING","OTP_ABUSE"]', 15, 2, "CRITICAL")
                )
                conn.execute(
                    "INSERT INTO correlation_rules (name, attack_types, time_window_minutes, min_alerts, escalate_severity) VALUES (?, ?, ?, ?, ?)",
                    ("Distributed + ATO combo", '["DISTRIBUTED_CREDENTIAL_STUFFING","ACCOUNT_TAKEOVER"]', 30, 2, "CRITICAL")
                )
                conn.commit()

            cur = conn.execute("SELECT COUNT(*) as c FROM users")
            if cur.fetchone()['c'] == 0:
                import hashlib
                pw_hash = hashlib.sha256("admin".encode()).hexdigest()
                conn.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                    ("admin", pw_hash, "admin")
                )
                conn.commit()

            cur = conn.execute("SELECT COUNT(*) as c FROM api_keys")
            if cur.fetchone()['c'] == 0:
                conn.execute(
                    "INSERT INTO api_keys (key_value, name) VALUES (?, ?)",
                    ("shieldai_dev_api_key_2026", "Default Dev Key")
                )
                conn.commit()

            cur = conn.execute("SELECT COUNT(*) as c FROM mitre_mappings")
            if cur.fetchone()['c'] == 0:
                mappings = [
                    ("CREDENTIAL_STUFFING", "TA0006", "Credential Access", "T1110.004", "Brute Force: Credential Stuffing", "Attacker stuffing multiple leaked credentials to gain access."),
                    ("ACCOUNT_TAKEOVER", "TA0001", "Initial Access", "T1078", "Valid Accounts", "Attacker gaining unauthorized access through existing valid credentials."),
                    ("BOT_SCRAPING", "TA0009", "Collection", "T1119", "Automated Collection", "Automated bot harvesting sensitive platform resources and data."),
                    ("BUSINESS_LOGIC", "TA0040", "Impact", "T1496", "Resource Hijacking", "Abusing logical flaws in checkout, promotion, or core features."),
                    ("COUPON_ABUSE", "TA0040", "Impact", "T1496", "Resource Hijacking", "Systemic exploitation of discounts or promotional codes."),
                    ("OTP_ABUSE", "TA0040", "Impact", "T1496", "Resource Hijacking", "Exploiting multi-factor / OTP flow to inflate SMS/telephony billing.")
                ]
                for m in mappings:
                    conn.execute(
                        "INSERT INTO mitre_mappings (attack_type, tactic_id, tactic_name, technique_id, technique_name, description) VALUES (?, ?, ?, ?, ?, ?)",
                        m
                    )
                conn.commit()

            cur = conn.execute("SELECT COUNT(*) as c FROM cisa_kev")
            if cur.fetchone()['c'] == 0:
                kevs = [
                    ("CVE-2021-44228", "Apache", "Log4j", "Apache Log4j2 Remote Code Execution Vulnerability", "2021-12-10", "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.", "Apply updates per vendor instructions."),
                    ("CVE-2021-34473", "Microsoft", "Exchange Server", "Microsoft Exchange Server Remote Code Execution Vulnerability", "2021-07-13", "Microsoft Exchange Server vulnerability allowing remote code execution via ProxyShell.", "Apply updates per vendor instructions."),
                    ("CVE-2023-38606", "Apple", "multiple products", "Apple iOS and macOS Kernel State Vulnerability", "2023-07-24", "An issue in Apple kernel state permitting memory access and arbitrary code execution.", "Apply updates per vendor instructions.")
                ]
                for k in kevs:
                    conn.execute(
                        "INSERT INTO cisa_kev (cve_id, vendor_project, product, vulnerability_name, date_added, short_description, required_action) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        k
                    )
                conn.commit()

            cur = conn.execute("SELECT COUNT(*) as c FROM cve_feed")
            if cur.fetchone()['c'] == 0:
                cves = [
                    ("CVE-2023-44487", "The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly.", 7.5, "HIGH", "2023-10-10", "2023-10-20"),
                    ("CVE-2023-38545", "A flaw in curl could allow an attacker to trigger a heap-based buffer overflow.", 9.8, "CRITICAL", "2023-10-18", "2023-10-25"),
                    ("CVE-2024-21626", "A vulnerability in runc allowing container breakout.", 8.6, "HIGH", "2024-01-31", "2024-02-05")
                ]
                for c in cves:
                    conn.execute(
                        "INSERT INTO cve_feed (cve_id, description, cvss_score, severity, published_date, last_modified_date) VALUES (?, ?, ?, ?, ?, ?)",
                        c
                    )
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to seed initial data: {e}")

@contextmanager
def get_db():
    pg_conn = get_postgres_connection()
    sl_conn = None
    if not pg_conn:
        sl_conn = sqlite3.connect(DB_PATH)
        sl_conn.row_factory = sqlite3.Row
    
    conn = UnifiedConnection(pg_conn=pg_conn, sl_conn=sl_conn)
    try:
        yield conn
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()
