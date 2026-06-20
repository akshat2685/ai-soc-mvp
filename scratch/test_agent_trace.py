import os
import sys
import logging

# Set up logging to console to see the PromptLoader details
logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

# Add backend directory to sys.path
backend_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend")
sys.path.append(backend_dir)

from database import init_db, get_db
from agents.graph import run_soc_investigation
from agents.prompts import PromptLoader

def test_live_agent_run():
    print("=== Step 1: Initializing database and seeding baseline data ===")
    init_db()

    # Seed mock telemetry log in SQLite logs table matching our test task
    print("\n=== Step 2: Injecting test telemetry for IP 198.51.100.45 ===")
    with get_db() as conn:
        conn.execute(
            "INSERT INTO logs (event_type, source_ip, user_id, status, endpoint, method) "
            "VALUES ('MITRE_T1110', '198.51.100.45', 'user_admin', 'FAILED', '/api/v1/login', 'POST')"
        )
        # Create a mock alert
        conn.execute(
            "INSERT INTO alerts (title, severity, attacker_ip, attack_type, verdict) "
            "VALUES ('Brute Force from 198.51.100.45', 'HIGH', '198.51.100.45', 'CREDENTIAL_STUFFING', 'PENDING')"
        )
        conn.commit()

    print("\n=== Step 3: Running dynamic agent society investigation ===")
    # Run the hierarchical agent graph investigation
    task_desc = "Investigate incident alert ID 1: Brute Force from IP 198.51.100.45"
    result = run_soc_investigation(task_desc)

    print("\n=== Step 4: Verifying structured outputs from specialist agents ===")
    findings = result.get("findings", {})
    
    # 1. Threat Hunter (Triage)
    th_findings = findings.get("threat_hunter", {})
    print(f"\nThreat Hunter (Triage Analyst Agent) Output:")
    print(f"  - Verdict: {th_findings.get('verdict')}")
    print(f"  - Confidence: {th_findings.get('confidence')}")
    print(f"  - MITRE Techniques: {th_findings.get('mitre_techniques')}")
    print(f"  - Evidence Summary: {th_findings.get('evidence_summary')}")

    # 2. Knowledge (Threat Intel)
    ki_findings = findings.get("knowledge", {})
    print(f"\nKnowledge (Threat Intel Agent) Output:")
    print(f"  - Indicator: {ki_findings.get('indicator')}")
    print(f"  - Reputation Score: {ki_findings.get('reputation_score')}")
    print(f"  - Threat Actor: {ki_findings.get('threat_actor')}")
    print(f"  - Campaign: {ki_findings.get('campaign')}")

    # 3. Root Cause (DevSecOps)
    rc_findings = findings.get("root_cause", {})
    print(f"\nRoot Cause (DevSecOps Agent) Output:")
    print(f"  - Asset ID: {rc_findings.get('asset_id')}")
    print(f"  - Vulnerabilities: {rc_findings.get('vulnerabilities')}")
    print(f"  - Remediation Options: {rc_findings.get('remediation_options')}")

    # 4. SOAR (Response Coordinator)
    soar_findings = findings.get("soar", {})
    print(f"\nSOAR (Response Coordinator Agent) Output:")
    print(f"  - Playbook Selected: {soar_findings.get('playbook_selected')}")
    print(f"  - Auto Execute: {soar_findings.get('auto_execute')}")
    print(f"  - Remediation Commands: {soar_findings.get('remediation_commands')}")

    print("\n=== Step 5: Checking immutable Audit Trail logs ===")
    with get_db() as conn:
        cur = conn.execute("SELECT action_type, triggered_by, execution_result, notes FROM audit_log ORDER BY id DESC LIMIT 10")
        rows = cur.fetchall()
        for row in reversed(rows):
            print(f"  [{row['triggered_by']}] {row['action_type']} -> Result: {row['execution_result']}")
            print(f"    Details: {row['notes']}\n")

if __name__ == "__main__":
    test_live_agent_run()
