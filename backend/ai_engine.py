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

def generate_alert_summary(alert_title: str, evidence: dict) -> str:
    prompt = f"""You are an AI security analyst in a SOC platform. Summarize this security alert in 2-3 clear sentences for an analyst.

Alert Type: {alert_title}
Evidence: {json.dumps(evidence)}

Be specific about what happened, the key indicators, and why this is suspicious. Do NOT invent facts not present in the evidence."""

    fallback = (
        f"AI Triage: Detected high-confidence {alert_title}. "
        f"Evidence shows anomalous activity from IP {evidence.get('source_ip')} "
        f"with {evidence.get('event_count', 'N/A')} suspicious events observed. "
        f"Immediate autonomous response has been triggered."
    )
    return _call_llm(prompt, fallback)

def generate_attacker_report(attacker_ip: str, events: list, attack_type: str) -> str:
    event_types = set(e.get('event_type', 'unknown') for e in events)
    user_agents = set(e.get('user_agent', 'unknown') for e in events if e.get('user_agent'))
    endpoints = set(e.get('endpoint', 'unknown') for e in events if e.get('endpoint'))
    user_ids = set(e.get('user_id', 'unknown') for e in events if e.get('user_id'))
    device_ids = set(e.get('device_id', 'unknown') for e in events if e.get('device_id'))

    prompt = f"""You are a threat intelligence analyst. Generate a detailed attacker intelligence report in markdown format.

Attacker IP: {attacker_ip}
Attack Type: {attack_type}
Total Malicious Events: {len(events)}
Targeted Endpoints: {', '.join(endpoints)}
User Agents Used: {', '.join(user_agents)}
Targeted User IDs: {', '.join(user_ids)}
Device IDs Seen: {', '.join(device_ids)}
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
- **Device Fingerprints:** {', '.join(device_ids) if device_ids else 'N/A'}

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

def generate_deterrence_email(attacker_ip: str, report: str, attack_type: str) -> str:
    prompt = f"""You are a cybersecurity legal communication specialist. Write a formal deterrence email to send to the abuse contact of the ISP owning IP {attacker_ip}.

Attack Type: {attack_type}
Intelligence Report:
{report}

The email should be professional, cite the specific attack activity, reference that evidence has been preserved, and warn of escalation. Include subject line."""

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
