"""Cyber Digital Twin Simulation Engine.

Simulates containment actions (Host Isolation, Account Disablement, and IP Blocking)
to calculate blast radius and business disruption scores. Supports both Neo4j graphs
and local SQLite fallbacks.
"""
from __future__ import annotations

import logging
import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from database import get_db
from .engine import run_cypher

log = logging.getLogger(__name__)

def simulate_containment_action(
    action_type: str,
    target: str,
    context: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Simulate a containment action to evaluate its blast radius and disruption.

    Args:
        action_type: HOST_ISOLATION, ACCOUNT_DISABLEMENT, or IP_BLOCK.
        target: The target identifier (IP, hostname, username, or database ID).
        context: Optional dictionary containing metadata.

    Returns:
        Dict containing simulation results: blast_radius_score, disruption_score,
        recommendation, affected_assets, and critical_assets_compromised.
    """
    sim_id = f"sim-cont-{uuid.uuid4().hex[:8]}"
    action_type = action_type.upper()
    
    log.info("Simulating containment %s on target %s", action_type, target)
    
    # Defaults
    blast_radius_score = 0.0
    disruption_score = 0.0
    affected_assets: List[str] = []
    critical_assets_compromised = 0
    notes = ""

    # Attempt Neo4j simulation first
    neo4j_success = False
    try:
        from backend.memory.connections import get_neo4j
        driver = get_neo4j()
        if driver:
            if action_type == "HOST_ISOLATION":
                cypher = (
                    "MATCH p=(start)-[*1..3]-(target) "
                    "WHERE (start.id = $target OR start.name = $target OR start.value = $target OR start.ip = $target) "
                    "RETURN DISTINCT target.id as id, target.criticality as criticality"
                )
                records = run_cypher(cypher, target=target)
                if records:
                    neo4j_success = True
                    affected_assets = [r["id"] for r in records if r["id"]]
                    critical_assets_compromised = sum(
                        1 for r in records if str(r.get("criticality", "")).upper() in {"CRITICAL", "HIGH"}
                    )
                    
            elif action_type == "ACCOUNT_DISABLEMENT":
                cypher = (
                    "MATCH (u:User)-[:LOGGED_INTO]->(h:Host) "
                    "WHERE u.id = $target OR u.name = $target "
                    "RETURN h.id as id, h.criticality as criticality"
                )
                records = run_cypher(cypher, target=target)
                if records:
                    neo4j_success = True
                    affected_assets = [r["id"] for r in records if r["id"]]
                    critical_assets_compromised = sum(
                        1 for r in records if str(r.get("criticality", "")).upper() in {"CRITICAL", "HIGH"}
                    )
                    
            elif action_type == "IP_BLOCK":
                cypher = (
                    "MATCH (start)-[:CONNECTED_TO|COMMUNICATED_WITH]-(target) "
                    "WHERE start.ip = $target OR start.id = $target "
                    "RETURN target.id as id, target.criticality as criticality"
                )
                records = run_cypher(cypher, target=target)
                if records:
                    neo4j_success = True
                    affected_assets = [r["id"] for r in records if r["id"]]
                    critical_assets_compromised = sum(
                        1 for r in records if str(r.get("criticality", "")).upper() in {"CRITICAL", "HIGH"}
                    )
    except Exception as e:
        log.warning("Neo4j simulation failed, using SQLite fallback: %s", e)

    # SQLite fallback if Neo4j is offline or returned no records
    if not neo4j_success:
        with get_db() as conn:
            if action_type == "HOST_ISOLATION":
                # Look up target host in assets
                cur = conn.execute(
                    "SELECT ip_address, hostname, criticality FROM assets "
                    "WHERE id = ? OR hostname = ? OR ip_address = ?",
                    (target, target, target)
                )
                row = cur.fetchone()
                if row:
                    affected_assets.append(row["hostname"])
                    ip = row["ip_address"]
                    crit = str(row["criticality"]).upper()
                    if crit in {"CRITICAL", "HIGH"}:
                        critical_assets_compromised += 1
                    
                    # Estimate subnet-based blast radius (sharing same /24 network prefix)
                    if ip and "." in ip:
                        subnet_prefix = ".".join(ip.split(".")[:3]) + ".%"
                        cur_subnet = conn.execute(
                            "SELECT hostname, criticality FROM assets WHERE ip_address LIKE ? AND ip_address != ?",
                            (subnet_prefix, ip)
                        )
                        for sub_row in cur_subnet.fetchall():
                            affected_assets.append(sub_row["hostname"])
                            if str(sub_row["criticality"]).upper() in {"CRITICAL", "HIGH"}:
                                critical_assets_compromised += 1
                else:
                    affected_assets.append(target)

            elif action_type == "ACCOUNT_DISABLEMENT":
                # Look up user in user_memory
                cur = conn.execute(
                    "SELECT user_id, risk_profile FROM user_memory WHERE user_id = ?",
                    (target,)
                )
                row = cur.fetchone()
                user_risk = "LOW"
                if row:
                    user_risk = str(row["risk_profile"]).upper()
                
                # Check logs for hosts this user accessed recently
                cur_logs = conn.execute(
                    "SELECT DISTINCT device_id FROM logs WHERE user_id = ? AND device_id IS NOT NULL",
                    (target,)
                )
                for log_row in cur_logs.fetchall():
                    dev_id = log_row["device_id"]
                    affected_assets.append(dev_id)
                    cur_ast = conn.execute("SELECT criticality FROM assets WHERE hostname = ? OR ip_address = ?", (dev_id, dev_id))
                    ast_row = cur_ast.fetchone()
                    if ast_row and str(ast_row["criticality"]).upper() in {"CRITICAL", "HIGH"}:
                        critical_assets_compromised += 1
                
                if not affected_assets:
                    affected_assets.append(f"user-session-{target}")
                    if user_risk in {"HIGH", "CRITICAL"}:
                        critical_assets_compromised += 1

            elif action_type == "IP_BLOCK":
                # Check if IP is internal (belongs to our assets)
                cur = conn.execute(
                    "SELECT hostname, criticality FROM assets WHERE ip_address = ?",
                    (target,)
                )
                row = cur.fetchone()
                if row:
                    affected_assets.append(row["hostname"])
                    if str(row["criticality"]).upper() in {"CRITICAL", "HIGH"}:
                        critical_assets_compromised += 1
                else:
                    # External IP block: check if it communicated with any internal assets
                    cur_logs = conn.execute(
                        "SELECT DISTINCT device_id FROM logs WHERE source_ip = ? AND device_id IS NOT NULL",
                        (target,)
                    )
                    for log_row in cur_logs.fetchall():
                        dev_id = log_row["device_id"]
                        affected_assets.append(dev_id)
                        cur_ast = conn.execute("SELECT criticality FROM assets WHERE hostname = ? OR ip_address = ?", (dev_id, dev_id))
                        ast_row = cur_ast.fetchone()
                        if ast_row and str(ast_row["criticality"]).upper() in {"CRITICAL", "HIGH"}:
                            critical_assets_compromised += 1

    # Get total asset count to normalize blast radius score
    with get_db() as conn:
        cur = conn.execute("SELECT COUNT(*) as count FROM assets")
        total_assets = cur.fetchone()["count"]
        if total_assets <= 0:
            total_assets = 20

    total_affected = len(affected_assets)
    blast_radius_score = min(1.0, round(total_affected / total_assets, 4))
    
    # Calculate Disruption score based on criticality and targets
    if action_type == "HOST_ISOLATION":
        crit_score = 0.2
        with get_db() as conn:
            cur = conn.execute(
                "SELECT criticality FROM assets WHERE id = ? OR hostname = ? OR ip_address = ?",
                (target, target, target)
            )
            row = cur.fetchone()
            if row:
                crit = str(row["criticality"]).upper()
                if crit == "CRITICAL":
                    crit_score = 0.9
                elif crit == "HIGH":
                    crit_score = 0.7
                elif crit == "MEDIUM":
                    crit_score = 0.4
        disruption_score = crit_score + (0.05 * len(affected_assets))
        
    elif action_type == "ACCOUNT_DISABLEMENT":
        crit_score = 0.2
        with get_db() as conn:
            cur = conn.execute("SELECT risk_profile FROM user_memory WHERE user_id = ?", (target,))
            row = cur.fetchone()
            if row:
                risk = str(row["risk_profile"]).upper()
                if risk in {"CRITICAL", "HIGH"}:
                    crit_score = 0.8
                elif risk == "MEDIUM":
                    crit_score = 0.5
        disruption_score = crit_score + (0.04 * len(affected_assets))
        
    elif action_type == "IP_BLOCK":
        is_internal = False
        with get_db() as conn:
            cur = conn.execute("SELECT criticality FROM assets WHERE ip_address = ?", (target,))
            row = cur.fetchone()
            if row:
                is_internal = True
                crit = str(row["criticality"]).upper()
                if crit == "CRITICAL":
                    crit_score = 0.95
                elif crit == "HIGH":
                    crit_score = 0.8
                else:
                    crit_score = 0.6
                disruption_score = crit_score
            else:
                disruption_score = min(0.3, 0.02 * len(affected_assets))

    disruption_score = min(1.0, round(disruption_score, 4))
    
    # Determine recommendation
    if disruption_score > 0.7:
        recommendation = "REQUIRES_APPROVAL"
        notes = f"Disruption score ({disruption_score}) is high. Target: {target}. Enforcing human-in-the-loop approval."
    else:
        recommendation = "APPROVE_AUTO_EXECUTE"
        notes = f"Disruption score ({disruption_score}) is within acceptable limit. Safe to execute automatically."

    # Record simulation run log in DB
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO simulations (sim_id, name, type, start_time, status) VALUES (?, ?, ?, ?, ?)",
                (sim_id, f"Simulated {action_type} on {target}", action_type, datetime.now(timezone.utc), "COMPLETED")
            )
            conn.execute(
                "INSERT INTO evaluations (eval_id, sim_id, mttd, mttr, precision, recall, f1_score) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (f"eval-{sim_id[9:]}", sim_id, 0.0, 0.0, disruption_score, blast_radius_score, float(critical_assets_compromised))
            )
            conn.commit()
    except Exception as db_err:
        log.warning("Could not write simulation metadata to database: %s", db_err)

    return {
        "sim_id": sim_id,
        "status": "success",
        "action_type": action_type,
        "target": target,
        "blast_radius_score": blast_radius_score,
        "disruption_score": disruption_score,
        "recommendation": recommendation,
        "affected_assets": affected_assets,
        "critical_assets_compromised": critical_assets_compromised,
        "notes": notes
    }
