import json
from database import get_db
from mitre_engine import get_mitre_mapping

KILL_CHAIN_STAGES = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact"
]

def build_attack_graph(incident_id: int) -> dict:
    """
    Reconstructs the attack path for a given incident by mapping its alerts
    onto the MITRE ATT&CK Kill Chain phases chronologically.
    """
    with get_db() as conn:
        cur = conn.execute(
            "SELECT id, timestamp, title, severity, attack_type, attacker_ip, device_fingerprint "
            "FROM alerts WHERE incident_id = ? ORDER BY timestamp ASC",
            (incident_id,)
        )
        alerts = [dict(row) for row in cur.fetchall()]
        
    if not alerts:
        return {"status": "error", "message": f"No alerts found for incident {incident_id}"}
        
    graph = {stage: [] for stage in KILL_CHAIN_STAGES}
    graph["Unknown Phase"] = []
    
    nodes = []
    edges = []
    
    prev_node_id = None
    
    for idx, alert in enumerate(alerts):
        mitre_map = get_mitre_mapping(alert["attack_type"])
        tactic_name = mitre_map.get("tactic_name", "Unknown Phase")
        
        # Place in the kill chain bucket
        if tactic_name in graph:
            graph[tactic_name].append(alert)
        else:
            graph["Unknown Phase"].append(alert)
            
        node_id = f"alert_{alert['id']}"
        nodes.append({
            "id": node_id,
            "label": alert["title"],
            "tactic": tactic_name,
            "technique": mitre_map.get("technique_id", ""),
            "timestamp": alert["timestamp"],
            "attacker_ip": alert.get("attacker_ip")
        })
        
        # Create chronological edges to represent lateral movement/progression
        if prev_node_id:
            edges.append({
                "source": prev_node_id,
                "target": node_id,
                "relationship": "followed_by"
            })
        
        prev_node_id = node_id
        
    # Remove empty stages to compress the response
    active_stages = {k: v for k, v in graph.items() if v}
    
    return {
        "incident_id": incident_id,
        "attack_path": nodes,
        "edges": edges,
        "kill_chain_distribution": active_stages
    }

def forecast_next_stages(incident_id: int) -> dict:
    """Predicts the next logical stages in the MITRE ATT&CK chain for this incident.

    Based on the sequence of alerts present in the incident.
    """
    graph_data = build_attack_graph(incident_id)
    if "status" in graph_data and graph_data["status"] == "error":
        return graph_data

    active_stages = list(graph_data["kill_chain_distribution"].keys())
    
    # Determine the furthest active stage index
    max_index = -1
    for stage in active_stages:
        if stage in KILL_CHAIN_STAGES:
            max_index = max(max_index, KILL_CHAIN_STAGES.index(stage))

    forecasted = []
    
    # If no stage is detected, forecast Initial Access
    if max_index == -1:
        forecasted.append({
            "tactic": "Initial Access",
            "probability": 0.9,
            "reason": "Incident initialized with no defined kill chain stage. Initial Access is the primary entry vector."
        })
    else:
        # Forecast the next 2 logical stages
        next_idx_1 = max_index + 1
        next_idx_2 = max_index + 2
        
        if next_idx_1 < len(KILL_CHAIN_STAGES):
            tactic = KILL_CHAIN_STAGES[next_idx_1]
            prob = 0.85 - (0.05 * next_idx_1)
            forecasted.append({
                "tactic": tactic,
                "probability": max(0.5, round(prob, 2)),
                "reason": f"Logical progression from current furthest stage: '{KILL_CHAIN_STAGES[max_index]}'."
            })
            
        if next_idx_2 < len(KILL_CHAIN_STAGES):
            tactic = KILL_CHAIN_STAGES[next_idx_2]
            prob = 0.70 - (0.05 * next_idx_2)
            forecasted.append({
                "tactic": tactic,
                "probability": max(0.3, round(prob, 2)),
                "reason": f"Secondary progression node in the attack trajectory."
            })
            
    # Always include lateral movement or impact if they are not already reached
    if "Lateral Movement" not in active_stages and max_index >= KILL_CHAIN_STAGES.index("Initial Access"):
        if not any(f["tactic"] == "Lateral Movement" for f in forecasted):
            forecasted.append({
                "tactic": "Lateral Movement",
                "probability": 0.65,
                "reason": "Lateral movement threat exists after successful Initial Access/Execution."
            })
            
    return {
        "incident_id": incident_id,
        "current_stages": active_stages,
        "forecasted_stages": forecasted
    }

def calculate_path_probabilities(incident_id: int) -> list:
    """Calculates compromise propagation path probabilities for assets linked to this incident.

    Integrates asset vulnerability profiles (CVSS scores) to refine probabilities.
    """
    paths = []
    
    with get_db() as conn:
        # 1. Fetch alerts for the incident
        cur_alerts = conn.execute(
            "SELECT id, title, attack_type, attacker_ip FROM alerts WHERE incident_id = ?",
            (incident_id,)
        )
        alerts = cur_alerts.fetchall()
        
        for alert in alerts:
            alert_id = alert["id"]
            # Try to find corresponding investigation to get targeted host/ip
            cur_inv = conn.execute(
                "SELECT collected_assets, collected_vulnerabilities FROM investigations WHERE alert_id = ?",
                (alert_id,)
            )
            inv = cur_inv.fetchone()
            if not inv:
                continue
                
            try:
                assets = json.loads(inv["collected_assets"] or "[]")
                vulns = json.loads(inv["collected_vulnerabilities"] or "[]")
            except Exception:
                continue
                
            for asset in assets:
                asset_ip = asset.get("ip_address")
                hostname = asset.get("hostname", "Unknown Host")
                if not asset_ip:
                    continue
                    
                # Look up asset criticality (using actual schema ip_address, hostname)
                cur_crit = conn.execute(
                    "SELECT ip_address, hostname, criticality FROM assets WHERE ip_address = ? OR hostname = ?",
                    (asset_ip, hostname)
                )
                crit_row = cur_crit.fetchone()
                criticality = str(crit_row["criticality"]).upper() if crit_row else "MEDIUM"
                
                # Check for CVEs on this asset
                asset_vulns = [v for v in vulns if v.get("ip_address") == asset_ip]
                
                base_prob = 0.5
                reason = "Standard network connectivity path."
                
                if asset_vulns:
                    # Find highest CVSS score
                    max_cvss = 5.0
                    cve_id = ""
                    for v in asset_vulns:
                        c_id = v.get("cve_id", "")
                        cur_cve = conn.execute("SELECT cvss_score FROM cve_feed WHERE cve_id = ?", (c_id,))
                        cve_row = cur_cve.fetchone()
                        if cve_row and cve_row["cvss_score"] > max_cvss:
                            max_cvss = cve_row["cvss_score"]
                            cve_id = c_id
                    
                    base_prob = max_cvss / 10.0
                    reason = f"High probability path due to exploit vulnerability {cve_id or 'CVE'} (CVSS {max_cvss})."
                else:
                    # Fallback to general criticality weighting
                    if criticality == "CRITICAL":
                        base_prob = 0.75
                        reason = "Critical asset path traversal probability."
                    elif criticality == "HIGH":
                        base_prob = 0.65
                        reason = "High importance asset path traversal probability."
                
                paths.append({
                    "source": f"alert_{alert_id}",
                    "target": asset.get("asset_id") or asset.get("hostname") or f"asset_{asset_ip}",
                    "probability": round(base_prob, 4),
                    "type": "exploitation" if asset_vulns else "connection",
                    "details": reason
                })
                
    return paths

