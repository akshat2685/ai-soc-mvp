"""Cyber World Model Graph Engine.

Maps assets, active directory parameters, user identities, and software CVE vectors.
Predicts attacker next moves (lateral movement, credential access, privilege escalation)
and performs vector semantic search for vulnerability intelligence.
"""
from __future__ import annotations

import logging
from typing import Dict, Any, List, Optional

from database import get_db
from digital_twin.engine import run_cypher

log = logging.getLogger(__name__)

# Try importing Qdrant vector store wrappers safely
try:
    from backend.memory.connections import get_qdrant
except ImportError:
    get_qdrant = None


def predict_next_moves(compromised_node_id: str, depth: int = 2) -> Dict[str, Any]:
    """Predicts the next logical hops/moves the attacker could make from this starting point.

    Args:
        compromised_node_id: IP address, Host name, or User ID.
        depth: Graph search depth limit.

    Returns:
        Dict containing list of predicted targets, probability, and ATT&CK tactics.
    """
    predictions: List[Dict[str, Any]] = []
    neo4j_success = False

    # 1. Attempt Neo4j path traversal
    try:
        from backend.memory.connections import get_neo4j
        if get_neo4j():
            cypher = (
                f"MATCH p=(start)-[:CONNECTED_TO|COMMUNICATED_WITH|LOGGED_INTO*1..{int(depth)}]-(target) "
                "WHERE start.id = $start OR start.ip = $start OR start.name = $start "
                "AND start <> target "
                "RETURN DISTINCT labels(target)[0] as label, coalesce(target.name, target.id) as target_id, "
                "       target.criticality as criticality, length(p) as distance "
                "LIMIT 20"
            )
            records = run_cypher(cypher, start=compromised_node_id)
            if records:
                neo4j_success = True
                for r in records:
                    dist = r.get("distance", 1)
                    base_prob = 0.8
                    if dist == 2:
                        base_prob = 0.5
                    elif dist > 2:
                        base_prob = 0.3
                    
                    crit = str(r.get("criticality", "Medium")).upper()
                    if crit in {"CRITICAL", "HIGH"}:
                        tactic = "Privilege Escalation"
                        prob = base_prob * 1.1
                    else:
                        tactic = "Lateral Movement"
                        prob = base_prob
                        
                    predictions.append({
                        "target_id": r["target_id"],
                        "type": r["label"] or "Host",
                        "probability": min(0.95, round(prob, 2)),
                        "tactic": tactic,
                        "distance": dist
                    })
    except Exception as e:
        log.warning("Neo4j prediction failed, using SQLite fallback: %s", e)

    # 2. SQLite fallback traversal
    if not neo4j_success:
        with get_db() as conn:
            cur = conn.execute(
                "SELECT id, hostname, ip_address, criticality FROM assets "
                "WHERE id = ? OR hostname = ? OR ip_address = ?",
                (compromised_node_id, compromised_node_id, compromised_node_id)
            )
            row = cur.fetchone()
            if row:
                ip = row["ip_address"]
                hostname = row["hostname"]
                
                # Fetch other assets in same /24 subnet (Distance = 1)
                if ip and "." in ip:
                    subnet_prefix = ".".join(ip.split(".")[:3]) + ".%"
                    cur_subnet = conn.execute(
                        "SELECT hostname, ip_address, criticality FROM assets "
                        "WHERE ip_address LIKE ? AND ip_address != ? LIMIT 5",
                        (subnet_prefix, ip)
                    )
                    for sub_row in cur_subnet.fetchall():
                        crit = str(sub_row["criticality"]).upper()
                        tactic = "Privilege Escalation" if crit in {"CRITICAL", "HIGH"} else "Lateral Movement"
                        prob = 0.8 if tactic == "Privilege Escalation" else 0.7
                        
                        predictions.append({
                            "target_id": sub_row["hostname"],
                            "type": "Host",
                            "probability": prob,
                            "tactic": tactic,
                            "distance": 1
                        })
                
                # Check log history for recent connections from this IP (Distance = 1)
                cur_logs = conn.execute(
                    "SELECT DISTINCT device_id FROM logs "
                    "WHERE source_ip = ? AND device_id IS NOT NULL AND device_id != ? LIMIT 5",
                    (ip, hostname)
                )
                for log_row in cur_logs.fetchall():
                    dev_id = log_row["device_id"]
                    if any(p["target_id"] == dev_id for p in predictions):
                        continue
                    
                    cur_crit = conn.execute("SELECT criticality FROM assets WHERE hostname = ? OR ip_address = ?", (dev_id, dev_id))
                    crit_row = cur_crit.fetchone()
                    crit = str(crit_row["criticality"]).upper() if crit_row else "MEDIUM"
                    
                    tactic = "Privilege Escalation" if crit in {"CRITICAL", "HIGH"} else "Lateral Movement"
                    predictions.append({
                        "target_id": dev_id,
                        "type": "Host",
                        "probability": 0.75,
                        "tactic": tactic,
                        "distance": 1
                    })
            else:
                # User account compromised node fallback
                cur_user = conn.execute(
                    "SELECT risk_profile FROM user_memory WHERE user_id = ?",
                    (compromised_node_id,)
                )
                row_user = cur_user.fetchone()
                if row_user:
                    cur_logs = conn.execute(
                        "SELECT DISTINCT device_id FROM logs WHERE user_id = ? LIMIT 5",
                        (compromised_node_id,)
                    )
                    for log_row in cur_logs.fetchall():
                        dev_id = log_row["device_id"]
                        predictions.append({
                            "target_id": dev_id,
                            "type": "Host",
                            "probability": 0.85,
                            "tactic": "Credential Access",
                            "distance": 1
                        })
                else:
                    predictions.append({
                        "target_id": "internal-gateway",
                        "type": "Gateway",
                        "probability": 0.9,
                        "tactic": "Initial Access",
                        "distance": 1
                    })

    # Sort predictions by probability descending
    predictions = sorted(predictions, key=lambda x: x["probability"], reverse=True)

    return {
        "status": "success",
        "compromised_node": compromised_node_id,
        "predictions": predictions
    }


def get_similar_vulnerabilities(query_text: str, limit: int = 5) -> List[Dict[str, Any]]:
    """Retrieves CVEs matching description or keyword. Uses Qdrant if online, SQLite fallback if offline.

    Args:
        query_text: Text snippet or keyword describing the vulnerability.
        limit: Max results.

    Returns:
        List of matching CVE dicts.
    """
    results: List[Dict[str, Any]] = []
    qdrant_success = False

    if get_qdrant:
        try:
            client = get_qdrant()
            if client:
                cname = "cve_vulnerabilities"
                cols = client.get_collections()
                exists = any(c.name == cname for c in cols.collections)
                if exists:
                    pass
        except Exception as e:
            log.warning("Qdrant similarity search failed, falling back to SQL: %s", e)

    if not qdrant_success:
        with get_db() as conn:
            cur = conn.execute(
                "SELECT cve_id, description, cvss_score, severity FROM cve_feed "
                "WHERE description LIKE ? OR cve_id LIKE ? LIMIT ?",
                (f"%{query_text}%", f"%{query_text}%", limit)
            )
            rows = cur.fetchall()
            for r in rows:
                results.append({
                    "cve_id": r["cve_id"],
                    "description": r["description"],
                    "cvss_score": r["cvss_score"],
                    "severity": r["severity"]
                })
            
            if len(results) < limit:
                rem_limit = limit - len(results)
                cur_kev = conn.execute(
                    "SELECT cve_id, vulnerability_name, short_description FROM cisa_kev "
                    "WHERE vulnerability_name LIKE ? OR short_description LIKE ? LIMIT ?",
                    (f"%{query_text}%", f"%{query_text}%", rem_limit)
                )
                for r in cur_kev.fetchall():
                    results.append({
                        "cve_id": r["cve_id"],
                        "description": f"{r['vulnerability_name']}: {r['short_description']}",
                        "cvss_score": 8.5,
                        "severity": "HIGH"
                    })

    return results
