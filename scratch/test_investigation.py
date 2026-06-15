import sys
import os
import json

# Add backend to path
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "backend"))

from database import init_db, get_db
from investigation_engine import run_investigation

def test_pipeline():
    init_db()
    
    print("[TEST] Seeding mock logs, asset, vulnerability for investigation...")
    with get_db() as conn:
        # Seed an asset
        conn.execute("INSERT OR REPLACE INTO assets (ip_address, hostname, owner, os, criticality) VALUES (?, ?, ?, ?, ?)",
                     ("192.168.1.50", "prod-web-server", "admin", "Linux Ubuntu", "HIGH"))
        
        # Seed a vulnerability
        conn.execute("INSERT OR REPLACE INTO vulnerabilities (ip_address, cve_id, severity, title, description, tool_source) VALUES (?, ?, ?, ?, ?, ?)",
                     ("192.168.1.50", "CVE-2026-9999", "CRITICAL", "Remote Code Execution in Web Server", "Critical vulnerability allowing remote shell access.", "Nessus"))
        
        # Seed some logs
        conn.execute("INSERT INTO logs (event_type, source_ip, user_id, status, device_id, user_agent, endpoint) VALUES (?, ?, ?, ?, ?, ?, ?)",
                     ("login", "192.168.1.50", "user_admin", "failed", "dev_123", "Mozilla/5.0", "/login"))
        conn.execute("INSERT INTO logs (event_type, source_ip, user_id, status, device_id, user_agent, endpoint) VALUES (?, ?, ?, ?, ?, ?, ?)",
                     ("login", "192.168.1.50", "user_admin", "success", "dev_123", "Mozilla/5.0", "/login"))
        
        # Seed a mock alert
        evidence = {
            "source_ip": "192.168.1.50",
            "user_ids": ["user_admin"],
            "device_fingerprint": "mock_fp_123",
            "attack_type": "ACCOUNT_TAKEOVER"
        }
        cur = conn.execute(
            "INSERT INTO alerts (title, severity, confidence, confidence_score, attack_type, evidence, attacker_ip, device_fingerprint) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("Simulated Account Takeover Alert", "HIGH", "HIGH", 85, "ACCOUNT_TAKEOVER", json.dumps(evidence), "192.168.1.50", "mock_fp_123")
        )
        alert_id = cur.lastrowid
        conn.commit()
        
    print(f"[TEST] Seeding complete. Created alert ID: {alert_id}")
    print("[TEST] Running investigation engine...")
    
    report = run_investigation(alert_id)
    
    print("\n" + "=" * 60)
    print("      AI INVESTIGATION REPORT")
    print("=" * 60)
    print(f"Investigation ID: {report.get('investigation_id')}")
    print(f"Refined Confidence: {report.get('confidence_score')}/100")
    print(f"Probable Root Cause: {report.get('probable_root_cause')}")
    print(f"\nRecommended Remediation:\n{report.get('recommended_remediation')}")
    print(f"\nExecutive Summary:\n{report.get('executive_summary')}")
    print(f"\nTechnical Summary:\n{report.get('technical_summary')}")
    print("=" * 60)

if __name__ == "__main__":
    test_pipeline()
