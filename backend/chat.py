import json
from database import get_db
from ai_engine import _call_llm

def handle_chat(query: str) -> dict:
    """Process a natural language query from an analyst and return a grounded answer."""

    # Search alerts
    with get_db() as conn:
        cur = conn.execute("SELECT id, title, severity, attack_type, attacker_ip, llm_summary, timestamp FROM alerts ORDER BY timestamp DESC")
        all_alerts = [dict(r) for r in cur.fetchall()]

        cur = conn.execute("SELECT COUNT(*) as c FROM logs")
        log_count = cur.fetchone()["c"]

        cur = conn.execute("SELECT COUNT(*) as c FROM responses WHERE action_type = 'BLOCK_IP'")
        block_count = cur.fetchone()["c"]

    # Build context for the LLM
    alerts_summary = json.dumps(all_alerts, indent=2, default=str)

    prompt = f"""You are ShieldAI, an AI security analyst assistant embedded in a SOC dashboard. Answer the analyst's question using ONLY the data provided below. Do NOT invent facts.

CURRENT SOC DATA:
- Total Alerts: {len(all_alerts)}
- Total Logs Ingested: {log_count}
- Total IPs Blocked: {block_count}

ALERT DETAILS:
{alerts_summary}

ANALYST QUESTION: {query}

Respond concisely and helpfully. If the data doesn't contain the answer, say so. Reference specific alert IDs and IPs where possible."""

    fallback_answer = _generate_fallback_answer(query, all_alerts, log_count, block_count)
    answer = _call_llm(prompt, fallback_answer)

    return {
        "query": query,
        "answer": answer,
        "alerts_referenced": len(all_alerts),
    }


def _generate_fallback_answer(query: str, alerts: list, log_count: int, block_count: int) -> str:
    q = query.lower()

    if "how many" in q and "alert" in q:
        return f"There are currently {len(alerts)} alerts in the system."

    if "credential" in q or "stuffing" in q:
        cred_alerts = [a for a in alerts if a.get("attack_type") == "CREDENTIAL_STUFFING"]
        if cred_alerts:
            ips = ", ".join(a["attacker_ip"] for a in cred_alerts)
            return f"Found {len(cred_alerts)} credential stuffing alert(s) from IP(s): {ips}."
        return "No credential stuffing alerts found."

    if "otp" in q or "sms" in q:
        otp_alerts = [a for a in alerts if a.get("attack_type") == "OTP_ABUSE"]
        if otp_alerts:
            ips = ", ".join(a["attacker_ip"] for a in otp_alerts)
            return f"Found {len(otp_alerts)} OTP abuse alert(s) from IP(s): {ips}."
        return "No OTP abuse alerts found."

    if "bot" in q:
        bot_alerts = [a for a in alerts if a.get("attack_type") == "BOT_ACTIVITY"]
        if bot_alerts:
            ips = ", ".join(a["attacker_ip"] for a in bot_alerts)
            return f"Found {len(bot_alerts)} bot activity alert(s) from IP(s): {ips}."
        return "No bot activity alerts found."

    if "takeover" in q or "ato" in q:
        ato_alerts = [a for a in alerts if a.get("attack_type") == "ACCOUNT_TAKEOVER"]
        if ato_alerts:
            ips = ", ".join(a["attacker_ip"] for a in ato_alerts)
            return f"Found {len(ato_alerts)} account takeover alert(s) from IP(s): {ips}."
        return "No account takeover alerts found."

    if "block" in q:
        return f"The system has autonomously blocked {block_count} IP(s) so far."

    if "summary" in q or "overview" in q or "status" in q:
        types = {}
        for a in alerts:
            t = a.get("attack_type", "UNKNOWN")
            types[t] = types.get(t, 0) + 1
        breakdown = ", ".join(f"{v} {k}" for k, v in types.items())
        return f"Current status: {len(alerts)} total alerts ({breakdown}), {log_count} events ingested, {block_count} IPs blocked."

    return f"I found {len(alerts)} alerts and {log_count} ingested events. Could you be more specific about what you'd like to know?"
