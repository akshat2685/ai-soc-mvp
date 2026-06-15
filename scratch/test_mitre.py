import sys
import os

# Add backend to path
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "backend"))

from database import init_db, get_db
from mitre_engine import get_mitre_mapping, get_all_mitre_mappings
from investigation_engine import run_investigation

def test_mitre():
    init_db()
    
    print("[TEST] Verifying seeded MITRE mappings...")
    all_mappings = get_all_mitre_mappings()
    if not all_mappings:
        print("[FAIL] No MITRE mappings found in database.")
        sys.exit(1)
        
    print(f"[SUCCESS] Found {len(all_mappings)} MITRE mappings.")
    for m in all_mappings:
        print(f"  - {m['attack_type']} -> {m['technique_name']} ({m['technique_id']}) under Tactic: {m['tactic_name']}")
        
    print("\n[TEST] Resolving single mapping (CREDENTIAL_STUFFING)...")
    single = get_mitre_mapping("CREDENTIAL_STUFFING")
    assert single["technique_id"] == "T1110.004"
    print(f"[SUCCESS] Resolved CREDENTIAL_STUFFING to: {single['technique_name']}")

    print("\n[TEST] Triggering investigation with MITRE mapping...")
    # Seed an alert
    with get_db() as conn:
        import json
        evidence = {
            "source_ip": "192.168.1.100",
            "user_ids": ["admin_user"],
            "attack_type": "CREDENTIAL_STUFFING"
        }
        cur = conn.execute(
            "INSERT INTO alerts (title, severity, confidence, confidence_score, attack_type, evidence, attacker_ip) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("MITRE Test Alert Stuffing", "HIGH", "HIGH", 90, "CREDENTIAL_STUFFING", json.dumps(evidence), "192.168.1.100")
        )
        alert_id = cur.lastrowid
        conn.commit()

    report = run_investigation(alert_id)
    print("\n      AI MITRE INVESTIGATION REPORT")
    print("=" * 60)
    print(f"Confidence Score: {report.get('confidence_score')}/100")
    print(f"probable root cause: {report.get('probable_root_cause')}")
    print(f"Remediation:\n{report.get('recommended_remediation')}")
    print(f"\nExecutive Summary:\n{report.get('executive_summary')}")
    print(f"\nTechnical Summary:\n{report.get('technical_summary')}")
    print("=" * 60)
    
if __name__ == "__main__":
    test_mitre()
