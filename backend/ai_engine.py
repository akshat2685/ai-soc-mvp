"""AI Engine — LLM-powered triage, reporting, and deterrence email generation.

Upgraded with:
- Evidence citations (log IDs/timestamps) in all outputs
- Confidence scoring (structured output)
- Feedback-aware prompting (few-shot from analyst verdicts)
"""
import os
import json

# Try to import google.generativeai for real LLM; if unavailable, use fallback
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
_gemini_model = None


def _get_gemini_model():
    global _gemini_model
    if _gemini_model is None and GEMINI_API_KEY:
        try:
            import google.generativeai as genai
            genai.configure(api_key=GEMINI_API_KEY)
            _gemini_model = genai.GenerativeModel("gemini-2.0-flash")
        except Exception as e:
            print(f"[AI ENGINE] Failed to initialize Gemini: {e}")
    return _gemini_model


def _call_llm(prompt: str, fallback: str) -> str:
    model = _get_gemini_model()
    if model:
        try:
            response = model.generate_content(prompt)
            return response.text
        except Exception as e:
            print(f"[AI ENGINE] Gemini API call failed: {e}, using fallback.")
    return fallback


# ── Feedback Context ──

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


# ── Alert Summary with Evidence Citations ──

def generate_alert_summary(alert_title: str, evidence: dict,
                           related_logs: list = None) -> str:
    """Generate an AI triage summary with evidence citations."""
    feedback_ctx = _build_feedback_context(evidence.get('attack_type', ''))
    log_entries = _format_log_entries(related_logs) if related_logs else "N/A"
    confidence = evidence.get('confidence_score', 80)

    prompt = f"""You are an AI security analyst in a SOC platform. Summarize this security alert in 2-3 clear sentences for an analyst.

Alert Type: {alert_title}
Evidence: {json.dumps(evidence)}
Confidence Score: {confidence}/100

Related Log Entries (cite these by ID):
{log_entries}

CRITICAL INSTRUCTIONS:
1. For every claim, cite the specific log entry ID(s) that support it using [LOG-ID] format.
2. Be specific about what happened, the key indicators, and why this is suspicious.
3. Do NOT invent facts not present in the evidence or logs.
4. Start with the confidence assessment: "Confidence: {confidence}/100 — "
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

    return _call_llm(prompt, fallback)


# ── Attacker Intelligence Report ──

def generate_attacker_report(attacker_ip: str, events: list, attack_type: str) -> str:
    event_types = set(e.get('event_type', 'unknown') for e in events)
    user_agents = set(e.get('user_agent', 'unknown') for e in events if e.get('user_agent'))
    endpoints = set(e.get('endpoint', 'unknown') for e in events if e.get('endpoint'))
    user_ids = set(e.get('user_id', 'unknown') for e in events if e.get('user_id'))
    device_ids = set(e.get('device_id', 'unknown') for e in events if e.get('device_id'))
    fingerprints = set(e.get('device_fingerprint', '') for e in events if e.get('device_fingerprint'))

    prompt = f"""You are a threat intelligence analyst. Generate a detailed attacker intelligence report in markdown format.

Attacker IP: {attacker_ip}
Attack Type: {attack_type}
Total Malicious Events: {len(events)}
Targeted Endpoints: {', '.join(endpoints)}
User Agents Used: {', '.join(user_agents)}
Targeted User IDs: {', '.join(user_ids)}
Device IDs Seen: {', '.join(device_ids)}
Device Fingerprints: {', '.join(fingerprints)}
Event Types: {', '.join(event_types)}

Include sections: Executive Summary, Indicators of Compromise (IoCs), Attack Timeline Analysis, Threat Assessment, and Recommended Actions. Do NOT invent facts."""

    fallback = f"""## Attacker Intelligence Report

**Attacker IP:** {attacker_ip}
**Attack Type:** {attack_type}
**Confidence:** HIGH
**Events Analyzed:** {len(events)}

### Indicators of Compromise (IoCs)
- **Primary IP:** {attacker_ip}
- **Targeted Endpoints:** {', '.join(endpoints) if endpoints else 'N/A'}
- **User Agents:** {', '.join(user_agents) if user_agents else 'N/A'}
- **Targeted Accounts:** {', '.join(user_ids) if user_ids else 'N/A'}
- **Device Fingerprints:** {', '.join(fingerprints) if fingerprints else 'N/A'}

### Attack Timeline Analysis
This IP executed {len(events)} malicious events of type [{', '.join(event_types)}].
The attack pattern is consistent with automated tooling.

### Threat Assessment
**Severity:** HIGH — This actor demonstrates clear hostile intent with automated attack patterns.

### Recommended Actions
1. Block IP {attacker_ip} at WAF and network firewall.
2. Notify upstream ISP abuse contact.
3. Rotate any compromised credentials associated with targeted accounts.
4. Monitor for resumed activity from adjacent IP ranges."""
    return _call_llm(prompt, fallback)


# ── Deterrence Email ──

def generate_deterrence_email(attacker_ip: str, report: str, attack_type: str) -> str:
    prompt = f"""You are a cybersecurity legal communication specialist. Write a formal deterrence email to send to the abuse contact of the ISP owning IP {attacker_ip}.

Attack Type: {attack_type}
Intelligence Report:
{report}

The email should be professional, cite the specific attack activity, reference that evidence has been preserved, and warn of escalation. Include subject line.
NOTE: This email will be reviewed by legal/security team before sending."""

    fallback = f"""SUBJECT: Notice of Malicious Activity — {attack_type} — IP {attacker_ip}
TO: abuse@isp-of-{attacker_ip}.placeholder

Dear Abuse Team,

We are writing to formally notify you of sustained malicious activity originating from IP address {attacker_ip} against our infrastructure.

Our automated AI SOC platform has identified this IP as conducting a {attack_type} attack. The following intelligence has been compiled:

{report}

All connections from {attacker_ip} have been permanently blocked. Forensic evidence has been preserved.

We request that you investigate this IP and take appropriate action. Failure to respond may result in escalation to relevant CERTs and law enforcement.

Regards,
AI SOC Autonomous Defense System"""
    return _call_llm(prompt, fallback)


# ── NL-to-SQL Helper ──

def translate_natural_language_to_sql(query: str) -> str:
    """Translate a natural language question into a safe SQL SELECT query."""
    schema_context = """
Database schema (SQLite):
- logs: id, timestamp, event_type, source_ip, user_id, status, device_id, user_agent, endpoint, method, device_fingerprint, geo_country, geo_asn
- alerts: id, timestamp, title, severity, confidence, confidence_score, attack_type, evidence, attacker_ip, llm_summary, verdict, incident_id, device_fingerprint
- incidents: id, timestamp, title, severity, status, correlation_key, llm_summary, verdict
- responses: id, timestamp, action_type, target, details, alert_id, incident_id, response_tier, status, expires_at, approval_status
- threat_intel: ip, country, country_code, flag, isp, abuse_score, usage_type, source
- audit_log: id, timestamp, action_type, response_tier, target, alert_id, incident_id, evidence_snapshot, triggered_by, approval_status, execution_result
"""

    prompt = f"""You are a SQL query generator for a SOC database. Convert this natural language question into a SQLite SELECT query.

{schema_context}

QUESTION: {query}

RULES:
1. Return ONLY the SQL query, nothing else. No markdown, no explanation.
2. Only SELECT queries are allowed. No INSERT, UPDATE, DELETE, DROP, etc.
3. Always add LIMIT 100 to prevent huge result sets.
4. Use datetime functions for time-based queries (e.g., datetime('now', '-7 days')).
5. Use LIKE for partial text matching.
6. If the question cannot be answered with the schema, return: SELECT 'Question cannot be answered with available data' as error"""

    fallback = f"SELECT 'Unable to translate query: {query}' as error LIMIT 1"
    result = _call_llm(prompt, fallback)

    # Clean up — extract just the SQL
    result = result.strip()
    if result.startswith("```"):
        lines = result.split("\n")
        result = "\n".join(l for l in lines if not l.startswith("```"))
    result = result.strip().rstrip(";")

    return result
