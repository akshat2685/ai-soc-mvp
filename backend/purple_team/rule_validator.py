"""Detection Rule Validator.

Validates generated Sigma and YARA rules against a false positive corpus of benign
events (benign admin commands, standard login patterns, standard user-agents)
to prevent deploying noisy rules.
"""
from __future__ import annotations

import logging
import re
from typing import Dict, Any, List

log = logging.getLogger(__name__)

# Benign log corpus representing standard operations
BENIGN_CORPUS = [
    # Benign log 1: standard user login
    {
        "event_type": "USER_LOGIN",
        "user_id": "alice",
        "source_ip": "192.168.1.15",
        "status": "SUCCESS",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "cmd": None
    },
    # Benign log 2: standard developer cmd execution
    {
        "event_type": "PROCESS_EXECUTION",
        "user_id": "bob",
        "cmd": "git commit -m \"fix typo in documentation\"",
        "device_id": "dev-laptop-01"
    },
    # Benign log 3: administrator system update check
    {
        "event_type": "PROCESS_EXECUTION",
        "user_id": "sysadmin",
        "cmd": "apt-get update && apt-get upgrade --dry-run",
        "device_id": "prod-web-01"
    },
    # Benign log 4: normal healthcheck ping
    {
        "event_type": "HTTP_REQUEST",
        "endpoint": "/health",
        "method": "GET",
        "user_agent": "Consul-HealthCheck/1.12",
        "status": "200"
    }
]

def validate_detection_rules(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Evaluates generated rules against the benign log corpus to check for false positives.

    Args:
        rules: List of dicts, each with keys 'name', 'type' (SIGMA/YARA), and 'content' (rule text).

    Returns:
        List of validation outcome dicts containing status and false positive details.
    """
    log.info("Running false-positive validation check on %d detection rules", len(rules))
    
    validation_results = []
    
    for rule in rules:
        rule_name = rule.get("name", "Unnamed Rule")
        rule_type = str(rule.get("type", "SIGMA")).upper()
        rule_content = rule.get("content", "")
        
        matches = []
        
        # Simple evaluation simulator
        if rule_type == "YARA":
            # Extract strings section from YARA rule
            # Look for double-quoted strings in the rule content
            strings_to_find = re.findall(r'"([^"]+)"', rule_content)
            for item in BENIGN_CORPUS:
                cmd_val = item.get("cmd") or ""
                ua_val = item.get("user_agent") or ""
                end_val = item.get("endpoint") or ""
                
                # If any keyword is found in benign command/user-agent/endpoint, it triggers
                for s in strings_to_find:
                    if s.lower() in cmd_val.lower() or s.lower() in ua_val.lower() or s.lower() in end_val.lower():
                        matches.append({
                            "matched_string": s,
                            "benign_log": str(item)
                        })
                        break
                        
        else:  # SIGMA
            # Extract keywords or selection terms from Sigma rule
            # Look for colon/key terms: e.g. "selection:" followed by "apt-get" or "git"
            # We can search for words/phrases inside rule content
            terms_to_check = []
            # Extract strings inside single or double quotes
            terms_to_check.extend(re.findall(r"'([^']+)'", rule_content))
            terms_to_check.extend(re.findall(r'"([^"]+)"', rule_content))
            
            for item in BENIGN_CORPUS:
                cmd_val = item.get("cmd") or ""
                ep_val = item.get("endpoint") or ""
                status_val = item.get("status") or ""
                event_val = item.get("event_type") or ""
                
                for t in terms_to_check:
                    # Ignore short formatting words
                    if len(t) < 4 or t.upper() in {"SIGMA", "YARA", "RULE", "FALSE"}:
                        continue
                    if (t.lower() in cmd_val.lower() or 
                        t.lower() in ep_val.lower() or 
                        t.lower() in status_val.lower() or
                        t.lower() in event_val.lower()):
                        matches.append({
                            "matched_term": t,
                            "benign_log": str(item)
                        })
                        break

        # Calculate FPR
        total_benign_logs = len(BENIGN_CORPUS)
        triggered_count = len(matches)
        fpr = round(triggered_count / total_benign_logs, 4)
        
        # Determine status: fail if triggered on any benign logs
        if triggered_count > 0:
            status = "FAILED_FP_CHECK"
            msg = f"Rule '{rule_name}' triggered on benign logs. False Positive Rate: {fpr:.2%}. Validation failed."
        else:
            status = "PASSED_FP_CHECK"
            msg = f"Rule '{rule_name}' passed false positive validation with 0.00% FPR."
            
        validation_results.append({
            "rule_name": rule_name,
            "type": rule_type,
            "status": status,
            "false_positive_rate": fpr,
            "triggered_logs_count": triggered_count,
            "matching_log_samples": [m for m in matches[:3]], # Limit to first 3 matches
            "message": msg
        })
        
    return validation_results
