import json
from .core import call_llm

def _build_feedback_context(attack_type: str, limit: int = 5) -> str:
    """Fetch recent analyst verdicts for this attack type as few-shot examples."""
    try:
        from database import get_db
        with get_db() as conn:
            cur = conn.execute(
                "SELECT a.title, a.evidence, a.verdict, f.notes "
                "FROM alerts a LEFT JOIN analyst_feedback f ON a.id = f.alert_id "
                "WHERE a.attack_type = ? AND a.verdict != 'PENDING' "
                "ORDER BY a.timestamp DESC LIMIT ?",
                (attack_type, limit)
            )
            rows = [dict(r) for r in cur.fetchall()]

        if not rows:
            return ""

        context = "\n\nPAST ANALYST VERDICTS (use as calibration):\n"
        for r in rows:
            context += f"- Alert: {r['title']} → Verdict: {r['verdict']}"
            if r.get('notes'):
                context += f" (Analyst notes: {r['notes']})"
            context += "\n"
        return context
    except Exception:
        return ""


def _format_log_entries(logs: list, max_entries: int = 15) -> str:
    """Format log entries as citations for the LLM prompt."""
    if not logs:
        return "No specific log entries available."
    
    lines = []
    for log in logs[:max_entries]:
        if isinstance(log, dict):
            log_id = log.get('id', '?')
            ts = log.get('timestamp', '?')
            evt = log.get('event_type', '?')
            ip = log.get('source_ip', '?')
            uid = log.get('user_id', '-')
            status = log.get('status', '?')
            ua = log.get('user_agent', '-')
            ep = log.get('endpoint', '-')
            fp = log.get('device_fingerprint', '-')
            lines.append(
                f"[LOG-{log_id}] {ts} | {evt} | IP:{ip} | User:{uid} | "
                f"Status:{status} | UA:{ua} | EP:{ep} | FP:{fp}"
            )
    return "\n".join(lines)


def generate_alert_summary(alert_title: str, evidence: dict,
                           related_logs: list = None) -> str:
    """Generate an AI triage summary with evidence citations."""
    feedback_ctx = _build_feedback_context(evidence.get('attack_type', ''))
    log_entries = _format_log_entries(related_logs) if related_logs else "N/A"
    confidence = evidence.get('confidence_score', 80)

    # --- THREAT INTEL INTEGRATION (PHASE 3) ---
    threat_intel_ctx = ""
    target_ip = evidence.get('attacker_ip') or evidence.get('source_ip')
    if target_ip:
        from threat_intel import enrich_ip
        intel = enrich_ip(target_ip)
        if intel:
            threat_intel_ctx += f"\nThreat Intelligence for IP {target_ip}:\n- ISP: {intel.get('isp')}\n- Country: {intel.get('country')}\n- Abuse Score: {intel.get('abuse_score')}/100\n- Usage Type: {intel.get('usage_type')}\n"
            
    import re
    cves_found = set(re.findall(r"CVE-\d{4}-\d{4,7}", alert_title + " " + json.dumps(evidence)))
    if cves_found:
        from threat_intel_engine import check_cve, check_cve_kev
        threat_intel_ctx += "\nVulnerability Intelligence:\n"
        for cve in cves_found:
            cve_data = check_cve(cve)
            kev_data = check_cve_kev(cve)
            threat_intel_ctx += f"- {cve}: "
            if cve_data:
                threat_intel_ctx += f"{cve_data.get('severity')} severity. "
            if kev_data:
                threat_intel_ctx += "KNOWN EXPLOITED (CISA KEV). "
            threat_intel_ctx += "\n"

    prompt = f"""You are an AI security analyst in a SOC platform. Summarize this security alert in 2-3 clear sentences for an analyst.

Alert Type: {alert_title}
Evidence: {json.dumps(evidence)}
Confidence Score: {confidence}/100
{threat_intel_ctx}

Related Log Entries (cite these by ID):
{log_entries}

CRITICAL INSTRUCTIONS:
1. For every claim, cite the specific log entry ID(s) that support it using [LOG-ID] format.
2. Be specific about what happened, the key indicators, and why this is suspicious.
3. Incorporate any Threat Intelligence or Vulnerability details if provided.
4. Do NOT invent facts not present in the evidence or logs.
5. Start with the confidence assessment: "Confidence: {confidence}/100 — "
{feedback_ctx}"""

    fallback = (
        f"Confidence: {confidence}/100 — AI Triage: Detected high-confidence {alert_title}. "
        f"Evidence shows anomalous activity from IP {evidence.get('source_ip')} "
        f"with {evidence.get('event_count', 'N/A')} suspicious events observed. "
    )
    if related_logs:
        cited_ids = [f"LOG-{l.get('id', '?')}" for l in related_logs[:3] if isinstance(l, dict)]
        fallback += f"Key evidence: [{', '.join(cited_ids)}]. "
    fallback += "Immediate autonomous response has been triggered."

    return call_llm(prompt, fallback)
