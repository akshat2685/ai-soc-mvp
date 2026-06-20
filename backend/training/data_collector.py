import os
import json
import logging
from database import get_db

logger = logging.getLogger(__name__)

def collect_training_data(tenant_id: str = "default") -> str:
    """Collect security data from DB and export as JSONL instruction-response dataset."""
    os.makedirs("backend/training/data", exist_ok=True)
    output_path = "backend/training/data/dataset.jsonl"
    
    dataset = []
    
    with get_db() as conn:
        # 1. Collect Alert Triage instructions
        cur = conn.execute(
            "SELECT id, title, severity, attack_type, evidence, llm_summary, verdict FROM alerts WHERE tenant_id = ?",
            (tenant_id,)
        )
        alerts = [dict(r) for r in cur.fetchall()]
        
        for alert in alerts:
            instruction = f"Analyze the following alert title: '{alert['title']}' with severity '{alert['severity']}' and evidence '{alert['evidence']}'."
            response = {
                "verdict": alert.get("verdict", "TRUE_POSITIVE"),
                "attack_type": alert.get("attack_type", "UNKNOWN"),
                "summary": alert.get("llm_summary", "Suspicious activity detected.")
            }
            dataset.append({
                "instruction": instruction,
                "input": "",
                "output": json.dumps(response)
            })

        # 2. Collect SOAR playbooks logic
        cur = conn.execute(
            "SELECT playbook_name, target, status FROM soar_playbook_runs WHERE tenant_id = ?",
            (tenant_id,)
        )
        playbooks = [dict(r) for r in cur.fetchall()]
        
        for pb in playbooks:
            instruction = f"Recommend a mitigation response playbook for target: '{pb['target']}' with incident description."
            response = {
                "playbook_name": pb["playbook_name"],
                "expected_outcome": f"Playbook execution resulted in {pb['status']}."
            }
            dataset.append({
                "instruction": instruction,
                "input": "",
                "output": json.dumps(response)
            })

    # Save to JSONL
    with open(output_path, "w", encoding="utf-8") as f:
        for item in dataset:
            f.write(json.dumps(item) + "\n")
            
    logger.info(f"[SOAR Training] Saved {len(dataset)} instruction pairs to {output_path}")
    return output_path
