import re
import json
from database import get_db

# Basic regex patterns inspired by Loghub/Drain concepts
LOG_TEMPLATES = [
    {
        "type": "SSH_AUTH",
        "regex": r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<message>.*)",
        "anomalous_keywords": ["Failed password", "Invalid user", "Connection closed by authenticating user"]
    },
    {
        "type": "APACHE_ACCESS",
        "regex": r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\S+\s+(?P<user>\S+)\s+\[(?P<datetime>[^\]]+)\]\s+\"(?P<method>\w+)\s+(?P<path>[^\"]+)\"\s+(?P<status>\d+)\s+(?P<size>\d+)",
        "anomalous_keywords": ["/etc/passwd", "UNION SELECT", "<script>", "cmd.exe"]
    }
]

def parse_unstructured_log(raw_log: str) -> dict:
    """
    Parses a raw unstructured string log into a structured dictionary.
    Returns the parsed data, log type, and whether it matched an anomaly signature.
    """
    # Attempt JSON parsing for Cloud Logs
    try:
        json_log = json.loads(raw_log)
        if "eventSource" in json_log and "amazonaws.com" in json_log["eventSource"]:
            # AWS CloudTrail
            is_anomalous = json_log.get("eventName") in ["DeleteTrail", "StopLogging", "ConsoleLogin", "CreateUser"]
            return {
                "structured_data": json_log,
                "type": "AWS_CLOUDTRAIL",
                "is_anomalous": is_anomalous
            }
        elif "operationName" in json_log and "properties" in json_log:
            # Azure Activity
            is_anomalous = "delete" in json_log["operationName"].lower() or "roleAssignment" in json_log["operationName"]
            return {
                "structured_data": json_log,
                "type": "AZURE_ACTIVITY",
                "is_anomalous": is_anomalous
            }
        elif "kind" in json_log and json_log["kind"] == "Event" and "apiVersion" in json_log and "audit.k8s.io" in json_log["apiVersion"]:
            # K8s Audit
            is_anomalous = "exec" in json_log.get("requestURI", "") or "secrets" in json_log.get("requestURI", "")
            return {
                "structured_data": json_log,
                "type": "K8S_AUDIT",
                "is_anomalous": is_anomalous
            }
    except json.JSONDecodeError:
        pass # Fallback to regex

    for template in LOG_TEMPLATES:
        match = re.match(template["regex"], raw_log)
        if match:
            data = match.groupdict()
            is_anomalous = False
            
            # Check for anomaly signatures in the parsed message/path
            message_to_check = data.get("message", "") or data.get("path", "")
            for keyword in template["anomalous_keywords"]:
                if keyword in message_to_check:
                    is_anomalous = True
                    break
                    
            return {
                "structured_data": data,
                "type": template["type"],
                "is_anomalous": is_anomalous
            }
            
    # Fallback for unknown logs
    return {
        "structured_data": {"raw": raw_log},
        "type": "UNKNOWN",
        "is_anomalous": False
    }

def ingest_raw_log(raw_log: str, source_ip: str = "127.0.0.1"):
    """
    Entry point for raw SIEM logs. Parses them and inserts them into the SOC pipeline.
    """
    parsed = parse_unstructured_log(raw_log)
    
    # Store in database
    with get_db() as conn:
        conn.execute(
            "INSERT INTO logs (event_type, source_ip, method, endpoint, status, device_fingerprint) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                parsed["type"],
                parsed["structured_data"].get("ip", source_ip),
                parsed["structured_data"].get("method", "N/A"),
                parsed["structured_data"].get("path", "N/A")[:200], # Truncate long paths
                parsed["structured_data"].get("status", "N/A"),
                "loghub_parsed"
            )
        )
        conn.commit()
        
    # If anomalous, trigger the detection engine
    if parsed["is_anomalous"]:
        from detection import trigger_incident
        
        events = [{"event_type": parsed["type"], "raw_log": raw_log}]
        trigger_incident(
            title=f"Anomalous SIEM Log Detected ({parsed['type']})",
            attack_type="LOG_ANOMALY",
            severity="MEDIUM",
            attacker_ip=parsed["structured_data"].get("ip", source_ip),
            events=events,
            confidence_score=70,
            evidence_citations=[f"Matched anomalous keyword signature in {parsed['type']} log.", raw_log]
        )
        
    return parsed
