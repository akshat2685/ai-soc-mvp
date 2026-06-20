"""Seed the memory platform from the existing SOC (over HTTP) OR from a built-in
realistic dataset when the SOC is offline.

Usage:
    python -m scripts.seed_memory
    python -m scripts.seed_memory --demo   # forces the built-in dataset

This populates every layer so the retrieval/learning engines have something to
work with on the first run.
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path

# Make `backend.*` importable when run as a script
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.memory import soc_client  # noqa: E402
from backend.memory.modules import (  # noqa: E402
    agent_decisions,
    assets,
    detections,
    false_positives,
    incidents,
    investigations,
    iocs,
    lessons_learned,
    playbooks,
    threat_intel,
    user_behavior,
)
from backend.memory.store import graph as graph_store  # noqa: E402

log = logging.getLogger("seed")
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")


# ---------------------------------------------------------------------------
# Built-in realistic dataset (used when SOC is offline / for the demo)
# ---------------------------------------------------------------------------
def seed_demo_data() -> dict:
    """Populate memory with realistic SOC data so engines are demonstrable."""
    log.info("Seeding DEMO dataset into memory...")
    counts: dict[str, int] = {}

    # --- Threat actors / malware / campaign ---
    threat_intel.record_actor({
        "id": "ta_lazarus_clone",
        "name": "APT-CredStuffer",
        "aliases": ["DarkVPN", "CredHammer"],
        "ttps": ["T1110", "T1078", "T1071"],
        "description": "Threat actor specializing in credential stuffing against VPN and e-commerce login portals. Uses rotating residential proxies.",
        "confidence": 0.9, "source_reliability": 0.8,
    })
    threat_intel.record_malware({
        "id": "mal_sshdumper",
        "name": "SSHDumper",
        "techniques": ["T1003", "T1552"],
        "threat_actor": "ta_lazarus_clone",
    })
    counts["threat_actors"] = 1

    # --- Assets ---
    assets.record({"id": "asset_vpn_gateway", "name": "vpn-prod-01", "kind": "server",
                   "criticality": "CRITICAL", "owner": "infra-team",
                   "vulnerabilities": [{"cve": "CVE-2023-1234", "score": 9.8}],
                   "incident_history": ["inc_credstuff_001"]})
    assets.record({"id": "asset_auth_svc", "name": "auth-service-prod", "kind": "app",
                   "criticality": "HIGH", "owner": "platform-team"})
    counts["assets"] = 2

    # --- Past incident (the 'similar' one we want to recall later) ---
    incidents.record({
        "id": "inc_credstuff_001",
        "severity": "HIGH",
        "confidence": 0.9,
        "attack_type": "CREDENTIAL_STUFFING",
        "mitre_mapping": "T1110",
        "affected_assets": ["asset_vpn_gateway"],
        "affected_users": ["victim_user_42"],
        "investigation_summary": "Credential stuffing against VPN users. 6 failed logins from rotating IPs followed by account lockouts. Blocked at WAF.",
        "root_cause": "Weak password policy on VPN portal; no CAPTCHA on /auth/login.",
        "response_actions": [{"action": "BLOCK_IP", "target": "192.168.1.100"}],
        "resolution": "WAF rule added; password policy hardened; CAPTCHA deployed.",
        "verdict": "TRUE_POSITIVE",
        "correlation_key": "192.168.1.100",
    })
    counts["incidents"] = 1

    # --- Investigation tied to that incident ---
    investigations.record({
        "id": "inv_credstuff_001",
        "incident_id": "inc_credstuff_001",
        "evidence": ["6 failed login attempts in 30s", "rotating user_agents"],
        "reasoning_steps": ["threshold breach", "device fingerprint mismatch"],
        "conclusions": ["Automated credential stuffing tool"],
        "recommended_actions": ["block IP", "deploy CAPTCHA"],
        "summary_text": "Credential stuffing against VPN users via rotating proxies. Mitigated by WAF block + CAPTCHA.",
    })
    counts["investigations"] = 1

    # --- IOCs ---
    for ip in ["192.168.1.100", "203.0.113.45"]:
        iocs.observe(ioc_type="ip", value=ip, severity="HIGH",
                     incident_id="inc_credstuff_001", threat_actor="ta_lazarus_clone")
    counts["iocs"] = 2

    # --- Playbook ---
    playbooks.record({
        "id": "pb_cred_stuffing",
        "name": "Credential Stuffing Response",
        "steps": ["block_ip", "lock_accounts", "deploy_captcha", "notify_abuse"],
        "triggers": ["CREDENTIAL_STUFFING"],
        "success_rate": 0.92, "failure_rate": 0.08,
        "avg_execution_sec": 45.0, "executions": 12,
    })
    counts["playbooks"] = 1

    # --- Detection rule ---
    detections.record({
        "id": "det_login_burst",
        "rule_type": "sigma",
        "logic": "5+ failed logins from one IP in 60s",
        "true_positives": 9, "false_positives": 1, "false_negatives": 2,
    })
    counts["detections"] = 1

    # --- Lesson learned ---
    lessons_learned.record({
        "id": "ll_credstuff_001",
        "incident_id": "inc_credstuff_001",
        "what_happened": "Credential stuffing against VPN portal",
        "why_it_happened": "No CAPTCHA + weak password policy",
        "what_worked": "Adaptive threshold detection fired within 30s",
        "what_failed": "Initial WAF rule was too narrow; had to broaden to UA pattern",
        "recommendations": ["Always deploy CAPTCHA on auth endpoints", "Broaden WAF rules to UA patterns"],
    })
    counts["lessons"] = 1

    # --- False positive memory ---
    false_positives.record({
        "id": "fp_internal_scan_001",
        "detection_trigger": "port_scan",
        "investigation_outcome": "Internal vulnerability scanner",
        "reason": "Authenticated Nessus scanner from 10.0.0.5",
        "suppression_key": "port_scan",
    })
    counts["false_positives"] = 1

    # --- User behavior baseline + drift ---
    user_behavior.record_observation("victim_user_42", {
        "typical_login_hour_utc": 9,
        "typical_location": "US-East",
        "typical_devices": ["corp-laptop-7"],
        "typical_apps": ["slack", "email"],
        "typical_activity_level": 0.4,
        "drift_score": 0.8,  # high drift — being attacked
    })
    counts["user_behavior"] = 1

    # --- Graph relationships (blast radius) ---
    graph_store.upsert_ip("192.168.1.100", risk_score=0.95)
    graph_store.upsert_host("asset_vpn_gateway", name="vpn-prod-01", criticality="CRITICAL")
    graph_store.upsert_user("victim_user_42")
    graph_store.upsert_asset("asset_vpn_gateway", kind="server", criticality="CRITICAL", name="vpn-prod-01")
    graph_store.upsert_threat_actor("ta_lazarus_clone", name="APT-CredStuffer")
    graph_store.link(
        "LOGGED_INTO",
        from_label="User", from_key_field="id", from_key_value="victim_user_42",
        to_label="Host", to_key_field="id", to_key_value="asset_vpn_gateway",
        at="2026-06-01T09:00:00Z",
    )
    graph_store.link(
        "COMPROMISED_BY",
        from_label="Host", from_key_field="id", from_key_value="asset_vpn_gateway",
        to_label="ThreatActor", to_key_field="id", to_key_value="ta_lazarus_clone",
        since="2026-06-01T09:05:00Z",
    )
    graph_store.link(
        "TARGETS",
        from_label="ThreatActor", from_key_field="id", from_key_value="ta_lazarus_clone",
        to_label="Host", to_key_field="id", to_key_value="asset_vpn_gateway",
        since="2026-06-01T09:05:00Z",
    )
    counts["graph_edges"] = 3

    # --- Agent decision ---
    agent_decisions.record({
        "id": "ad_demo_001",
        "agent_role": "triage",
        "decision": "escalate_to_incident",
        "reasoning": "Threshold breach + device fingerprint mismatch + known threat actor linkage",
        "tool_calls": ["recall", "enrich_ip"],
        "outcome": "incident created",
        "confidence": 0.9, "success": True,
    })
    counts["agent_decisions"] = 1

    log.info("Demo dataset seeded: %s", counts)
    return counts


# ---------------------------------------------------------------------------
# Backfill from the live SOC (over HTTP)
# ---------------------------------------------------------------------------
def seed_from_soc() -> dict:
    """Pull existing incidents/alerts from the SOC and index them in memory."""
    if not soc_client.is_reachable():
        log.warning("SOC not reachable at %s — skipping backfill.", soc_client._get_client().base_url)
        return {"skipped": "soc_offline"}
    log.info("Backfilling memory from live SOC...")
    counts = {"incidents": 0, "iocs": 0}
    for inc in soc_client.get_incidents():
        incidents.record({
            "id": str(inc.get("id")),
            "severity": inc.get("severity"),
            "attack_type": inc.get("title") if "cred" in str(inc.get("title", "")).lower() else None,
            "investigation_summary": inc.get("description"),
            "correlation_key": inc.get("attacker_ip") or inc.get("correlation_key"),
            "status": inc.get("status"),
            "verdict": inc.get("verdict", "PENDING"),
        }, source="soc_backfill")
        counts["incidents"] += 1
        ip = inc.get("attacker_ip") or inc.get("correlation_key")
        if ip:
            iocs.observe(ioc_type="ip", value=ip, severity="HIGH", incident_id=str(inc.get("id")))
            counts["iocs"] += 1
    log.info("SOC backfill done: %s", counts)
    return counts


def main(demo: bool = False) -> int:
    if demo or not soc_client.is_reachable():
        seed_demo_data()
    else:
        seed_from_soc()
    return 0


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Seed the AI SOC memory platform")
    p.add_argument("--demo", action="store_true", help="force the built-in demo dataset")
    args = p.parse_args()
    sys.exit(main(demo=args.demo))
