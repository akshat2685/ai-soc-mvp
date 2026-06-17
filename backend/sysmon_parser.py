import os
import requests
import xml.etree.ElementTree as ET
from database import get_db, init_db

SYSMON_URL = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
LOCAL_XML = os.path.join(os.path.dirname(__file__), "..", "scratch", "sysmonconfig-export.xml")

def fetch_sysmon_config():
    if not os.path.exists(LOCAL_XML):
        print("[SYSMON] Downloading SwiftOnSecurity Sysmon config...")
        response = requests.get(SYSMON_URL)
        if response.status_code == 200:
            os.makedirs(os.path.dirname(LOCAL_XML), exist_ok=True)
            with open(LOCAL_XML, 'w', encoding='utf-8') as f:
                f.write(response.text)
            print("[SYSMON] Downloaded successfully.")
        else:
            print("[SYSMON] Failed to download config.")
            return False
    return True

def map_event_id(tag_name: str) -> int:
    mapping = {
        "ProcessCreate": 1,
        "NetworkConnect": 3,
        "RegistryEvent": 12, # Also 13, 14 but grouped
        "FileCreate": 11,
        "WmiEvent": 19,
        "DnsQuery": 22
    }
    return mapping.get(tag_name, 0)

def parse_and_ingest():
    if not fetch_sysmon_config():
        return
        
    print("[SYSMON] Parsing XML configuration...")
    tree = ET.parse(LOCAL_XML)
    root = tree.getroot()
    
    rules_added = 0
    with get_db() as conn:
        # Clear existing rules to prevent duplicates on re-run
        conn.execute("DELETE FROM endpoint_rules")
        
        # In sysmon XML, rules are under EventFiltering -> RuleGroup -> * (ProcessCreate, etc)
        event_filtering = root.find("EventFiltering")
        if event_filtering is not None:
            for rule_group in event_filtering.findall("RuleGroup"):
                for event_type in rule_group:
                    event_id = map_event_id(event_type.tag)
                    if event_id == 0:
                        continue
                    
                    onmatch = event_type.get("onmatch", "include")
                    # We usually want to alert on "include" rules because they specify what to log (which are often suspicious things)
                    # For SwiftOnSecurity, "exclude" reduces noise, "include" captures targeted bad stuff.
                    
                    for condition_node in event_type:
                        condition = condition_node.get("condition", "contains")
                        pattern = condition_node.text
                        name = condition_node.get("name")
                        
                        if pattern and name:
                            # Classify attack type based on name loosely
                            attack_type = "ENDPOINT_ANOMALY"
                            if "Ransomware" in name: attack_type = "RANSOMWARE"
                            elif "Credential" in name or "Mimikatz" in name: attack_type = "CREDENTIAL_DUMPING"
                            elif "Suspicious" in name: attack_type = "SUSPICIOUS_EXECUTION"
                            
                            conn.execute(
                                "INSERT INTO endpoint_rules (rule_name, event_id, condition, pattern, attack_type) "
                                "VALUES (?, ?, ?, ?, ?)",
                                (name, event_id, condition, pattern.strip(), attack_type)
                            )
                            rules_added += 1
        conn.commit()
    print(f"[SYSMON] Successfully ingested {rules_added} endpoint detection rules.")

if __name__ == "__main__":
    init_db()
    parse_and_ingest()
