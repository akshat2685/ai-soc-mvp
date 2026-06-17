from database import get_db

def get_mitre_mapping(attack_type: str) -> dict:
    """
    Returns the MITRE mapping (tactic_id, tactic_name, technique_id, technique_name, description)
    for a given attack type. If not found, returns a default mapping.
    """
    with get_db() as conn:
        cur = conn.execute(
            "SELECT tactic_id, tactic_name, technique_id, technique_name, description "
            "FROM mitre_mappings WHERE attack_type = ?",
            (attack_type,)
        )
        row = cur.fetchone()
        if row:
            return dict(row)
            
    # Default fallback
    return {
        "tactic_id": "TA0043",
        "tactic_name": "Reconnaissance",
        "technique_id": "T1595",
        "technique_name": "Active Scanning",
        "description": "General suspicious activity targeting system interfaces."
    }

def get_all_mitre_mappings() -> list[dict]:
    """
    Returns a list of all registered MITRE mappings in the database.
    """
    with get_db() as conn:
        cur = conn.execute("SELECT * FROM mitre_mappings ORDER BY attack_type ASC")
        return [dict(row) for row in cur.fetchall()]

def sync_mitre_stix():
    """
    Downloads the official MITRE ATT&CK Enterprise STIX JSON and populates a local knowledge graph table.
    """
    import requests
    import os
    
    MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    
    print("[MITRE] Downloading official MITRE ATT&CK STIX JSON...")
    resp = requests.get(MITRE_URL, timeout=15)
    if resp.status_code != 200:
        print("[MITRE] Failed to download STIX JSON.")
        return
        
    data = resp.json()
    objects = data.get("objects", [])
    
    with get_db() as conn:
        # Create a table for raw STIX objects if it doesn't exist
        conn.execute("""
            CREATE TABLE IF NOT EXISTS mitre_knowledge_graph (
                id TEXT PRIMARY KEY,
                type TEXT,
                name TEXT,
                description TEXT,
                external_id TEXT,
                url TEXT
            )
        """)
        conn.execute("DELETE FROM mitre_knowledge_graph")
        
        inserted = 0
        for obj in objects:
            if obj.get("type") in ["attack-pattern", "intrusion-set", "malware", "tool", "course-of-action"]:
                ext_refs = obj.get("external_references", [])
                mitre_ref = next((ref for ref in ext_refs if ref.get("source_name") == "mitre-attack"), {})
                
                conn.execute(
                    "INSERT INTO mitre_knowledge_graph (id, type, name, description, external_id, url) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        obj.get("id"),
                        obj.get("type"),
                        obj.get("name"),
                        obj.get("description"),
                        mitre_ref.get("external_id"),
                        mitre_ref.get("url")
                    )
                )
                inserted += 1
                
        conn.commit()
    print(f"[MITRE] Successfully ingested {inserted} objects into the Knowledge Graph.")

if __name__ == "__main__":
    sync_mitre_stix()
