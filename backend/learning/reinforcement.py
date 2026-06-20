import json
import logging
from typing import Dict, Any, List
from database import get_db
from purple_team.sigma_generator import generate_sigma_rule
from ai_engine import _call_llm

logger = logging.getLogger(__name__)

def init_reinforcement_tables():
    """Create learning and playbook optimization schemas if missing."""
    queries = [
        """
        CREATE TABLE IF NOT EXISTS playbook_optimizations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT DEFAULT 'default',
            playbook_name TEXT NOT NULL,
            action_name TEXT NOT NULL,
            failure_rate REAL,
            recommendation TEXT,
            applied INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS generated_yara_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_name TEXT UNIQUE NOT NULL,
            threat_context TEXT,
            rule_content TEXT NOT NULL,
            status TEXT DEFAULT 'STAGED',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """
    ]
    with get_db() as conn:
        for q in queries:
            try:
                conn.execute(q)
                conn.commit()
            except Exception as e:
                logger.error(f"[Learning Engine] Schema creation failed: {e}")

def run_reinforcement_optimization_loop(tenant_id: str = "default") -> dict:
    """Run closed-loop optimization assessing failures, staging rules, and updating configs."""
    init_reinforcement_tables()
    
    optimizations = []
    generated_rules = []

    # 1. Analyze playbooks execution history to identify flaky integrations
    with get_db() as conn:
        cur = conn.execute(
            """
            SELECT action_name, integration_name,
                   COUNT(*) as total,
                   SUM(CASE WHEN status = 'FAILED' THEN 1 ELSE 0 END) as failures
            FROM soar_action_runs
            GROUP BY action_name, integration_name
            """
        )
        action_stats = [dict(r) for r in cur.fetchall()]

    for stat in action_stats:
        total = stat["total"]
        failures = stat["failures"]
        fail_rate = float(failures / total) if total > 0 else 0.0

        if fail_rate > 0.5 and total >= 3:
            # Flaky connector detected -> Optimize playbook!
            rec = f"Substitute action '{stat['action_name']}' in playbooks: High failure rate ({int(fail_rate*100)}%). Fallback to Slack webhook alerting."
            with get_db() as conn:
                conn.execute(
                    """
                    INSERT INTO playbook_optimizations (tenant_id, playbook_name, action_name, failure_rate, recommendation)
                    VALUES (?, 'All', ?, ?, ?)
                    """,
                    (tenant_id, stat["action_name"], fail_rate, rec)
                )
                conn.commit()
            optimizations.append({
                "action": stat["action_name"],
                "failure_rate": fail_rate,
                "recommendation": rec
            })

    # 2. Identify missing detections from Purple Team logs and generate rules
    missed_techniques = []
    with get_db() as conn:
        cur_sim = conn.execute(
            "SELECT DISTINCT name FROM simulations WHERE name LIKE 'Purple Team validation:%'"
        )
        sims = [s[0] for s in cur_sim.fetchall()]
        for s in sims:
            # Extract technique ID e.g. T1110.004
            parts = s.split(":")
            if len(parts) > 1:
                tech_id = parts[1].strip()
                # Check if it was ever successfully detected
                cur_det = conn.execute(
                    "SELECT COUNT(*) as c FROM evaluations WHERE sim_id IN (SELECT sim_id FROM simulations WHERE name = ?) AND precision > 0.5",
                    (s,)
                )
                if cur_det.fetchone()["c"] == 0:
                    missed_techniques.append(tech_id)

    # Automatically generate rules for missed techniques
    for tech_id in list(set(missed_techniques))[:2]: # Limit to top 2 to avoid overhead
        # Generate Sigma
        try:
            sigma_res = generate_sigma_rule(tech_id, "Technique Validation Fail")
            generated_rules.append({
                "type": "Sigma",
                "target": tech_id,
                "rule_name": sigma_res.get("rule_yaml", "")[:50] + "..."
            })
        except Exception:
            pass

        # Generate YARA
        try:
            yara_res = generate_yara_rule(tech_id)
            generated_rules.append({
                "type": "YARA",
                "target": tech_id,
                "rule_name": yara_res.get("rule_name")
            })
        except Exception:
            pass

    return {
        "status": "success",
        "playbook_optimizations_found": len(optimizations),
        "optimizations": optimizations,
        "rules_generated_count": len(generated_rules),
        "rules": generated_rules
    }

from agents.prompts import PromptLoader

def generate_yara_rule(technique_id: str) -> dict:
    """Generate YARA rule targeting file signatures matching malicious techniques."""
    init_reinforcement_tables()
    base_prompt = f"""You are the EDYSOR YARA Rule Architect.
Generate a YARA rule for malware targeting MITRE Technique {technique_id}.
Return a valid YARA rule syntax. Include strings and condition.
"""
    prompt = PromptLoader.get_prompt("playbook_rl", base_prompt)
    yara_syntax = _call_llm(prompt, fallback=f"rule Malicious_{technique_id.replace('.', '_')} {{ strings: $s1 = \"eval(base64_decode\" condition: $s1 }}")
    
    rule_name = f"Detect_{technique_id.replace('.', '_')}"
    
    with get_db() as conn:
        try:
            conn.execute(
                "INSERT INTO generated_yara_rules (rule_name, threat_context, rule_content) VALUES (?, ?, ?)",
                (rule_name, f"MITRE {technique_id}", yara_syntax)
            )
            conn.commit()
        except Exception:
            pass
            
    return {
        "rule_name": rule_name,
        "yara_rule": yara_syntax
    }
