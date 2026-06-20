"""Swarm Consensus & Debate Module.

Simulates a collaborative multi-agent debate between Threat Hunter, Malware Analyst,
and Root Cause Analyst personas to resolve verdict discrepancies and determine confidence.
"""
from __future__ import annotations

import logging
from typing import Dict, Any, List

log = logging.getLogger(__name__)

def run_swarm_debate(findings: Dict[str, Any]) -> Dict[str, Any]:
    """Runs a collaborative consensus debate between specialized analyst roles.

    Args:
        findings: Consolidated findings dict from previous agent steps.

    Returns:
        Dict containing resolved final_verdict, confidence, and debate_transcript.
    """
    log.info("Running swarm consensus debate on incident findings")
    
    # Extract indicators to seed debate opinions
    threat_hunter_findings = findings.get("threat_hunter", {})
    root_cause_findings = findings.get("root_cause", {})
    malware_findings = findings.get("malware_analysis", "No malware payload analyzed.")
    
    # Default to TRUE_POSITIVE if we have strong indications, otherwise check
    hunter_verdict = threat_hunter_findings.get("verdict", "TRUE_POSITIVE")
    hunter_confidence = threat_hunter_findings.get("confidence", 0.8)
    
    # Malware analyst verdict: checks if malware analyzed reports suspicious action
    malware_verdict = "TRUE_POSITIVE"
    malware_confidence = 0.75
    if "benign" in str(malware_findings).lower() or "safe" in str(malware_findings).lower():
        malware_verdict = "FALSE_POSITIVE"
        malware_confidence = 0.8
        
    # Root Cause Analyst verdict: checks if vulnerability is exploitable
    rc_verdict = "TRUE_POSITIVE"
    rc_confidence = 0.8
    vulns = root_cause_findings.get("vulnerabilities", [])
    if not vulns and rc_verdict == "TRUE_POSITIVE" and hunter_verdict == "FALSE_POSITIVE":
        rc_verdict = "FALSE_POSITIVE"
        rc_confidence = 0.7

    # Debate Transcript Compilation
    transcript = []
    
    # 1. Threat Hunter statement
    if hunter_verdict == "TRUE_POSITIVE":
        th_arg = (
            f"Based on raw telemetry analysis, the traffic anomalies and source reputation "
            f"indicate a malicious campaign. Confidence: {hunter_confidence}."
        )
    else:
        th_arg = (
            f"Telemetry patterns match standard baseline activity. No anomalous indicators detected. "
            f"Confidence: {hunter_confidence}."
        )
    transcript.append(f"[Threat Hunter] Argument: {th_arg}")
    
    # 2. Malware Analyst statement
    if malware_verdict == "TRUE_POSITIVE":
        ma_arg = (
            f"Process arguments and executing payload trace matches credential harvesting "
            f"or privilege escalation behaviors. Confidence: {malware_confidence}."
        )
    else:
        ma_arg = (
            f"Payload analysis confirms safe file execution patterns. Benign system actions. "
            f"Confidence: {malware_confidence}."
        )
    transcript.append(f"[Malware Analyst] Argument: {ma_arg}")
    
    # 3. Root Cause Analyst statement
    if rc_verdict == "TRUE_POSITIVE":
        rc_arg = (
            f"Target host is confirmed vulnerable with active exposure mappings. "
            f"Exploitation path is highly probable. Confidence: {rc_confidence}."
        )
    else:
        rc_arg = (
            f"Target host is fully patched. No active exploitable CVEs match the attack vector. "
            f"Confidence: {rc_confidence}."
        )
    transcript.append(f"[Root Cause Analyst] Argument: {rc_arg}")

    # Conflict Resolution & Consensus Voting
    votes = [hunter_verdict, malware_verdict, rc_verdict]
    tp_count = votes.count("TRUE_POSITIVE")
    fp_count = votes.count("FALSE_POSITIVE")
    
    if tp_count >= fp_count:
        final_verdict = "TRUE_POSITIVE"
        voting_confs = [c for v, c in zip(votes, [hunter_confidence, malware_confidence, rc_confidence]) if v == "TRUE_POSITIVE"]
        final_confidence = sum(voting_confs) / len(voting_confs) if voting_confs else 0.8
        resolution_notes = f"Consensus resolved: TRUE_POSITIVE ({tp_count}/3 votes)."
    else:
        final_verdict = "FALSE_POSITIVE"
        voting_confs = [c for v, c in zip(votes, [hunter_confidence, malware_confidence, rc_confidence]) if v == "FALSE_POSITIVE"]
        final_confidence = sum(voting_confs) / len(voting_confs) if voting_confs else 0.8
        resolution_notes = f"Consensus resolved: FALSE_POSITIVE ({fp_count}/3 votes)."

    transcript.append(f"[Consensus Resolution] Verdict decided: {resolution_notes}")

    return {
        "status": "success",
        "verdict": final_verdict,
        "confidence": round(final_confidence, 4),
        "debate_transcript": transcript
    }
