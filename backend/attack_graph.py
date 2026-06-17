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
