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
