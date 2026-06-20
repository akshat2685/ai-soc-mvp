from .core import call_llm

def generate_attacker_report(attacker_ip: str, events: list, attack_type: str) -> str:
    event_types = set(e.get('event_type', 'unknown') for e in events)
    user_agents = set(e.get('user_agent', 'unknown') for e in events if e.get('user_agent'))
    endpoints = set(e.get('endpoint', 'unknown') for e in events if e.get('endpoint'))
    user_ids = set(e.get('user_id', 'unknown') for e in events if e.get('user_id'))
    device_ids = set(e.get('device_id', 'unknown') for e in events if e.get('device_id'))
    fingerprints = set(e.get('device_fingerprint', '') for e in events if e.get('device_fingerprint'))

    # --- THREAT INTEL INTEGRATION (PHASE 3) ---
    from threat_intel import enrich_ip
    intel = enrich_ip(attacker_ip)
    threat_intel_ctx = ""
    if intel:
        threat_intel_ctx = f"ISP: {intel.get('isp')}\nCountry: {intel.get('country')} {intel.get('flag', '')}\nAbuse Score: {intel.get('abuse_score')}/100\nUsage Type: {intel.get('usage_type')}"

    prompt = f"""You are a threat intelligence analyst. Generate a detailed attacker intelligence report in markdown format.

Attacker IP: {attacker_ip}
Threat Intel: 
{threat_intel_ctx}

Attack Type: {attack_type}
Total Malicious Events: {len(events)}
Targeted Endpoints: {', '.join(endpoints)}
User Agents Used: {', '.join(user_agents)}
Targeted User IDs: {', '.join(user_ids)}
Device IDs Seen: {', '.join(device_ids)}
Device Fingerprints: {', '.join(fingerprints)}
Event Types: {', '.join(event_types)}

Include sections: Executive Summary, Indicators of Compromise (IoCs), Attack Timeline Analysis, Threat Assessment, and Recommended Actions. Use the Threat Intel data in the Threat Assessment. Do NOT invent facts."""

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
    return call_llm(prompt, fallback)


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
    return call_llm(prompt, fallback)
