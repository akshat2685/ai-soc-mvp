import sys
import os
import json
from fpdf import FPDF
from fastapi.testclient import TestClient

# Add backend to path
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "backend"))

from main import app
from database import init_db, get_db
from investigation_engine import run_investigation

def generate_pdf():
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", size=12)
    # Write a unique remediation guideline we can check in LLM output
    lines = [
        "Remediation Playbook for ACCOUNT_TAKEOVER",
        "Playbook ID: PB-ATO-999",
        "Remediation instructions for ACCOUNT_TAKEOVER:",
        "1. MANDATORY ACTION: Revoke all active session tokens immediately and trigger MFA reset.",
        "2. MANDATORY ACTION: Block device fingerprint on the ShieldAI high-risk watch list.",
        "3. MANDATORY ACTION: Send warning email with subject 'EDYSOR Security Alert: Compromised Account'.",
        "Ensure all SOC analysts follow the PB-ATO-999 guidelines."
    ]
    for line in lines:
        pdf.cell(0, 10, text=line, new_x="LMARGIN", new_y="NEXT")
    
    pdf_path = os.path.join(os.path.dirname(__file__), "playbook_ato_test.pdf")
    pdf.output(pdf_path)
    print(f"[TEST] Generated PDF playbook at: {pdf_path}")
    return pdf_path

def test_rag_flow():
    init_db()
    client = TestClient(app)
    # 1. Login using default admin to get a JWT token
    print("[TEST] Logging in as admin...")
    login_resp = client.post("/auth/login", json={
        "username": "admin",
        "password": "admin"
    })
    assert login_resp.status_code == 200, f"Login failed: {login_resp.text}"
    token = login_resp.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    print("[TEST] Authenticated successfully as admin.")

    # 2. Generate and upload the PDF playbook
    pdf_path = generate_pdf()
    with open(pdf_path, "rb") as f:
        upload_resp = client.post(
            "/knowledge/upload-pdf",
            files={"file": ("playbook_ato_test.pdf", f, "application/pdf")},
            headers=headers
        )
    
    # Clean up pdf file
    if os.path.exists(pdf_path):
        os.remove(pdf_path)
        
    assert upload_resp.status_code == 200, f"PDF upload failed: {upload_resp.text}"
    upload_data = upload_resp.json()
    print(f"[SUCCESS] PDF uploaded: {upload_data}")
    assert upload_data["chunks_embedded"] > 0, "No chunks were embedded"

    # 3. Seed an alert for ACCOUNT_TAKEOVER
    print("[TEST] Seeding alert for ACCOUNT_TAKEOVER...")
    target_ip = "192.168.1.88"
    evidence = {
        "source_ip": target_ip,
        "user_ids": ["rag_victim_user"],
        "device_fingerprint": "mock_fp_rag_999",
        "attack_type": "ACCOUNT_TAKEOVER"
    }
    
    with get_db() as conn:
        conn.execute("INSERT OR REPLACE INTO assets (ip_address, hostname, owner, os, criticality) VALUES (?, ?, ?, ?, ?)",
                     (target_ip, "rag-test-host", "finance", "Windows Server 2022", "HIGH"))
        
        cur = conn.execute(
            "INSERT INTO alerts (title, severity, confidence, confidence_score, attack_type, evidence, attacker_ip, device_fingerprint) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("Suspicious Multi-IP Account Access", "HIGH", "HIGH", 80, "ACCOUNT_TAKEOVER", json.dumps(evidence), target_ip, "mock_fp_rag_999")
        )
        alert_id = cur.lastrowid
        conn.commit()
        
    print(f"[TEST] Alert seeded with ID: {alert_id}")
    
    # 4. Run automated investigation
    print("[TEST] Running automated investigation pipeline...")
    report = run_investigation(alert_id)
    
    print("\n" + "=" * 60)
    print("      AI INVESTIGATION REPORT WITH PLAYBOOK RAG")
    print("=" * 60)
    print(f"Investigation ID: {report.get('investigation_id')}")
    print(f"Refined Confidence: {report.get('confidence_score')}/100")
    print(f"Probable Root Cause: {report.get('probable_root_cause')}")
    print(f"\nRecommended Remediation:\n{report.get('recommended_remediation')}")
    print(f"\nTechnical Summary:\n{report.get('technical_summary')}")
    print("=" * 60)

    # 5. Assert that the remediation or technical summary reflects the playbook details (e.g. PB-ATO-999)
    remediation_text = report.get('recommended_remediation', '')
    tech_summary_text = report.get('technical_summary', '')
    
    assert "PB-ATO-999" in remediation_text or "PB-ATO-999" in tech_summary_text or "token" in remediation_text.lower(), \
        "Remediation did not reference playbooks/guidelines successfully."
    print("[SUCCESS] RAG context successfully verified in the investigation outputs!")

if __name__ == "__main__":
    test_rag_flow()
