import sqlite3
import os
from contextlib import contextmanager

DB_PATH = os.path.join(os.path.dirname(__file__), "soc.db")


def init_db():
    with get_db() as conn:
        # ── Core Tables ──
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
                device_fingerprint TEXT,
                geo_country TEXT,
                geo_asn TEXT
            )
        """)
        conn.execute("""
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
                incident_id INTEGER,
                response_tier INTEGER DEFAULT 4,
                status TEXT DEFAULT 'ACTIVE',
                expires_at DATETIME,
                approved_by TEXT,
                approval_status TEXT DEFAULT 'AUTO'
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

        # ── Layer 1: Detection Engine Tables ──
        conn.execute("""
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
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS correlation_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                attack_types TEXT,
                time_window_minutes INTEGER DEFAULT 30,
                min_alerts INTEGER DEFAULT 2,
                escalate_severity TEXT DEFAULT 'CRITICAL',
                enabled INTEGER DEFAULT 1
            )
        """)

        # ── Layer 2: AI Triage Feedback Table ──
        conn.execute("""
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
        """)

        # ── Layer 3: Response Engine Tables ──
        conn.execute("""
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
        """)
        conn.execute("""
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
        """)

        # ── Layer 4: Deterrence Email Drafts ──
        conn.execute("""
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
        """)

        # ── Layer 5: Users & Auth ──
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'analyst',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_login DATETIME,
                is_active INTEGER DEFAULT 1
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_value TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_used_at DATETIME,
                is_active INTEGER DEFAULT 1,
                user_id TEXT
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                cve_id TEXT,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                tool_source TEXT,
                discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.execute("""
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
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                hostname TEXT NOT NULL,
                owner TEXT,
                os TEXT,
                criticality TEXT NOT NULL,
                last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS virtual_patches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_name TEXT NOT NULL,
                target_endpoint TEXT NOT NULL,
                pattern_regex TEXT NOT NULL,
                action TEXT DEFAULT 'BLOCK',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.execute("""
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
                technical_summary TEXT,
                FOREIGN KEY(alert_id) REFERENCES alerts(id),
                FOREIGN KEY(incident_id) REFERENCES incidents(id)
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS mitre_mappings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                attack_type TEXT UNIQUE NOT NULL,
                tactic_id TEXT NOT NULL,
                tactic_name TEXT NOT NULL,
                technique_id TEXT NOT NULL,
                technique_name TEXT NOT NULL,
                description TEXT
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS cisa_kev (
                cve_id TEXT PRIMARY KEY,
                vendor_project TEXT,
                product TEXT,
                vulnerability_name TEXT,
                date_added TEXT,
                short_description TEXT,
                required_action TEXT
            )
        """)

        # ── Safe Migrations for Existing DBs ──
        _safe_add_column(conn, "logs", "device_fingerprint", "TEXT")
        _safe_add_column(conn, "logs", "geo_country", "TEXT")
        _safe_add_column(conn, "logs", "geo_asn", "TEXT")
        _safe_add_column(conn, "alerts", "incident_id", "INTEGER")
        _safe_add_column(conn, "alerts", "device_fingerprint", "TEXT")
        _safe_add_column(conn, "alerts", "confidence_score", "INTEGER DEFAULT 80")
        _safe_add_column(conn, "alerts", "evidence_citations", "TEXT")
        _safe_add_column(conn, "responses", "incident_id", "INTEGER")
        _safe_add_column(conn, "responses", "response_tier", "INTEGER DEFAULT 4")
        _safe_add_column(conn, "responses", "status", "TEXT DEFAULT 'ACTIVE'")
        _safe_add_column(conn, "responses", "expires_at", "DATETIME")
        _safe_add_column(conn, "responses", "approved_by", "TEXT")
        _safe_add_column(conn, "responses", "approval_status", "TEXT DEFAULT 'AUTO'")

        # ── Indexes ──
        conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_fingerprint ON logs(device_fingerprint)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_source_ip ON logs(source_ip)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_user_id ON logs(user_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_event_type ON logs(event_type)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_fingerprint_event ON logs(device_fingerprint, event_type, status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_user_event_status ON logs(user_id, event_type, status, timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ip_type ON alerts(attacker_ip, attack_type)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_incident_id ON alerts(incident_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_verdict ON alerts(verdict, attack_type)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_baselines_lookup ON entity_baselines(entity_type, entity_value, event_type)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_responses_status ON responses(status, expires_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_responses_alert ON responses(alert_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_pending_status ON pending_approvals(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_email_drafts_status ON email_drafts(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_feedback_attack ON analyst_feedback(attack_type, verdict)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip_address)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_vulns_ip ON vulnerabilities(ip_address)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_investigations_alert_id ON investigations(alert_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_investigations_incident_id ON investigations(incident_id)")

        # ── Seed default correlation rules ──
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

        # ── Seed default admin user (password: admin — change immediately) ──
        cur = conn.execute("SELECT COUNT(*) as c FROM users")
        if cur.fetchone()['c'] == 0:
            import hashlib
            pw_hash = hashlib.sha256("admin".encode()).hexdigest()
            conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                ("admin", pw_hash, "admin")
            )

        # ── Seed default development API key ──
        cur = conn.execute("SELECT COUNT(*) as c FROM api_keys")
        if cur.fetchone()['c'] == 0:
            conn.execute(
                "INSERT INTO api_keys (key_value, name) VALUES (?, ?)",
                ("shieldai_dev_api_key_2026", "Default Dev Key")
            )

        # ── Seed default MITRE mappings ──
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

        # ── Seed default CISA KEV entries ──
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


def _safe_add_column(conn, table, column, col_type):
    """Safely add a column to an existing table, ignoring if it already exists."""
    try:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")
    except sqlite3.OperationalError:
        pass  # column already exists


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()
