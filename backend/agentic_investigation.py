import json
from database import get_db
from ai_engine import _call_llm

def build_attack_graph(attacker_ip: str):
    """
    Agentic loop that reconstructs the attack chain by looking up
    all targeted users, endpoints, and devices related to the IP.
    """
    with get_db() as conn:
        # 1. Get all users targeted by this IP
        cur = conn.execute("SELECT DISTINCT user_id FROM logs WHERE source_ip = ? AND user_id IS NOT NULL", (attacker_ip,))
        targeted_users = [row["user_id"] for row in cur.fetchall()]

        # 2. Get all other IPs that have targeted those SAME users (indicating a distributed attack/botnet)
        other_ips = set()
        for user in targeted_users:
            cur = conn.execute("SELECT DISTINCT source_ip FROM logs WHERE user_id = ? AND source_ip != ?", (user, attacker_ip))
            other_ips.update(row["source_ip"] for row in cur.fetchall())

        # 3. Get all device_ids used by this IP
        cur = conn.execute("SELECT DISTINCT device_id FROM logs WHERE source_ip = ? AND device_id IS NOT NULL", (attacker_ip,))
        devices = [row["device_id"] for row in cur.fetchall()]

        # 4. Get all endpoints hit
        cur = conn.execute("SELECT DISTINCT endpoint FROM logs WHERE source_ip = ? AND endpoint IS NOT NULL", (attacker_ip,))
        endpoints = [row["endpoint"] for row in cur.fetchall()]

    # Generate Mermaid graph
    # We will build a simple flowchart
    mermaid_lines = ["graph TD", f"  IP_{attacker_ip.replace('.','_')}[IP: {attacker_ip}]:::attacker"]
    
    for user in targeted_users:
        mermaid_lines.append(f"  IP_{attacker_ip.replace('.','_')} -->|Targets| U_{user}[User: {user}]:::user")
        
    for ip in other_ips:
        mermaid_lines.append(f"  IP_{ip.replace('.','_')}[IP: {ip}]:::other_ip")
        for user in targeted_users:
            with get_db() as conn:
                cur = conn.execute("SELECT COUNT(*) as c FROM logs WHERE source_ip = ? AND user_id = ?", (ip, user))
                if cur.fetchone()['c'] > 0:
                    mermaid_lines.append(f"  IP_{ip.replace('.','_')} -.->|Also Targets| U_{user}")

    for dev in devices:
        mermaid_lines.append(f"  D_{dev.replace('-','_')}[Device: {dev}]:::device --> IP_{attacker_ip.replace('.','_')}")

    mermaid_lines.append("\n  classDef attacker fill:#ff4d4d,stroke:#333,stroke-width:2px,color:white;")
    mermaid_lines.append("  classDef user fill:#4d94ff,stroke:#333,stroke-width:2px,color:white;")
    mermaid_lines.append("  classDef other_ip fill:#ff9933,stroke:#333,stroke-width:1px;")
    mermaid_lines.append("  classDef device fill:#cccccc,stroke:#333,stroke-width:1px,color:black;")

    mermaid_code = "\n".join(mermaid_lines)

    # Use LLM to analyze the graph
    prompt = f"""You are an autonomous AI SOC investigator. Analyze the following attack chain graph data for IP {attacker_ip}:
Targeted Users: {targeted_users}
Other IPs targeting those users: {list(other_ips)}
Devices used: {devices}
Endpoints hit: {endpoints}

Write a 1-paragraph summary of your findings. State if this looks like a distributed attack, single actor, or targeted credential stuffing. Be authoritative and concise."""
    
    fallback = "The attack chain reveals multiple targeted users and endpoints originating from the primary attacker IP."
    if other_ips:
        fallback += " The presence of other IPs targeting the same users strongly suggests a distributed attack or botnet."

    analysis = _call_llm(prompt, fallback)

    return {
        "mermaid_code": mermaid_code,
        "analysis": analysis,
        "nodes": {
            "targeted_users": targeted_users,
            "other_ips": list(other_ips),
            "devices": devices,
            "endpoints": endpoints
        }
    }
