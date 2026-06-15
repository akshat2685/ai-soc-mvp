import sys
import os
import json

# Add backend to path
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "backend"))

from database import init_db, get_db
from threat_intel_engine import check_cve_kev
from investigation_engine import run_investigation

def test_threat_intel():
    init_db()
    
    print("[TEST] Checking CISA KEV entry lookup...")
    log4shell = check_cve_kev("CVE-2021-44228")
    if not log4shell:
        print("[FAIL] Seeded Log4Shell CVE not found.")
        sys.exit(1)
        
    print(f"[SUCCESS] Found KEV details: {log4shell['vulnerability_name']}")

    # Let's seed an asset and vulnerability for Apple Exploit
    target_ip = "192.168.1.99"
    cve_id = "CVE-2023-38606"  # Apple iOS Kernel (Seeded KEV)

    print(f"\n[TEST] Seeding host {target_ip} with CISA KEV vulnerability {cve_id}...")
    with get_db() as conn:
        conn.execute("INSERT OR REPLACE INTO assets (ip_address, hostname, owner, os, criticality) VALUES (?, ?, ?, ?, ?)",
                     (target_ip, "executive-macbook", "CEO", "macOS", "HIGH"))
                     
        conn.execute("INSERT OR REPLACE INTO vulnerabilities (ip_address, cve_id, severity, title, description, tool_source) VALUES (?, ?, ?, ?, ?, ?)",
                     (target_ip, cve_id, "HIGH", "Apple Kernel Vulnerability", "Exploit allowing memory access", "Nessus"))
                     
        # Seed telemetry logs for correlation
        conn.execute("INSERT INTO logs (event_type, source_ip, user_id, status, device_id, user_agent, endpoint) VALUES (?, ?, ?, ?, ?, ?, ?)",
                     ("api_call", "192.168.1.200", "ceo_user", "failed", "dev_mac", "curl", "/api/v1/debug"))
        
        # Seed an alert for intrusion targeting this KEV vuln
        evidence = {
            "source_ip": "192.168.1.200",
            "target_ip": target_ip,
            "attack_type": "EXPLOIT_ATTEMPT",
            "user_ids": ["ceo_user"]
        }
        
        cur = conn.execute(
            "INSERT INTO alerts (title, severity, confidence, confidence_score, attack_type, evidence, attacker_ip) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("IDS Alert: Apple kernel exploitation attempt", "HIGH", "HIGH", 80, "EXPLOIT_ATTEMPT", json.dumps(evidence), "192.168.1.200")
        )
        alert_id = cur.lastrowid
        conn.commit()

    print(f"[SUCCESS] Seeded alert ID: {alert_id}")
    print("[TEST] Running investigation pipeline on alert...")
    
    report = run_investigation(alert_id)
    
    print("\n      AI THREAT INTEL INVESTIGATION REPORT")
    print("=" * 60)
    print(f"Confidence Score: {report.get('confidence_score')}/100")
    print(f"probable root cause: {report.get('probable_root_cause')}")
    print(f"Remediation:\n{report.get('recommended_remediation')}")
    print(f"\nExecutive Summary:\n{report.get('executive_summary')}")
    print(f"\nTechnical Summary:\n{report.get('technical_summary')}")
    print("=" * 60)
    
    # Assert confidence score reflects the KEV boost
    # Base 80 + 10 (critical asset HIGH) + 15 (vulnerabilities) + 20 (CISA KEV match) = 100/100
    assert report.get("confidence_score") == 100
    print("[SUCCESS] Confidence score successfully elevated to 100 due to KEV risk matching!")

if __name__ == "__main__":
    test_threat_intel()
