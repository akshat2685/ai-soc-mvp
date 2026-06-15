"""SOC Chat Assistant — AI-powered analyst Q&A with NL-to-SQL capabilities.

Supports:
- General SOC status queries
- Natural language → SQL translation for historical data queries
- Grounded answers from live database context
"""
import json
from database import get_db
from ai_engine import _call_llm, translate_natural_language_to_sql


def handle_chat(query: str) -> dict:
    """Process a natural language query from an analyst and return a grounded answer."""

    # Step 1: Classify intent
    intent = _classify_query_intent(query)

    if intent == "data_query":
        return _handle_data_query(query)
    else:
        return _handle_general_query(query)


def _classify_query_intent(query: str) -> str:
    """Determine if this is a data query (needs SQL) or general Q&A."""
    q = query.lower()

    # Keywords that indicate a data query
    data_keywords = [
        'show me', 'list all', 'how many', 'find', 'search', 'query',
        'last 7 days', 'last 24 hours', 'last week', 'last month',
        'from ip', 'from asn', 'from country', 'targeting',
        'between', 'since', 'before', 'after', 'top',
        'count', 'total', 'average', 'most', 'least',
        'which', 'what ips', 'what users', 'what endpoints',
    ]

    if any(kw in q for kw in data_keywords):
        return "data_query"

    return "general"


def _handle_data_query(query: str) -> dict:
    """Translate natural language to SQL, execute safely, and summarize results."""

    # Step 1: Translate to SQL
    sql = translate_natural_language_to_sql(query)

    # Step 2: Validate — only SELECT allowed
    if not sql.strip().upper().startswith("SELECT"):
        return {
            "query": query,
            "answer": "I can only execute read-only queries for security reasons.",
            "sql_generated": sql,
            "alerts_referenced": 0,
        }

    # Step 3: Ensure LIMIT exists
    if "LIMIT" not in sql.upper():
        sql = sql.rstrip(";") + " LIMIT 100"

    # Step 4: Execute safely
    try:
        with get_db() as conn:
            cur = conn.execute(sql)
            columns = [desc[0] for desc in cur.description] if cur.description else []
            rows = [dict(zip(columns, row)) for row in cur.fetchall()]
    except Exception as e:
        return {
            "query": query,
            "answer": f"I tried to query the database but encountered an error: {str(e)}. "
                      f"The SQL I generated was: `{sql}`",
            "sql_generated": sql,
            "alerts_referenced": 0,
        }

    # Step 5: Summarize results with LLM
    if not rows:
        answer = f"No results found for your query. (SQL: `{sql}`)"
    elif len(rows) == 1 and 'error' in rows[0]:
        answer = rows[0]['error']
    else:
        results_str = json.dumps(rows[:50], indent=2, default=str)
        prompt = f"""You are ShieldAI, an AI security analyst assistant. Summarize these database query results for the analyst.

ANALYST QUESTION: {query}
SQL EXECUTED: {sql}
RESULTS ({len(rows)} rows):
{results_str}

Provide a concise, helpful summary. Reference specific IPs, users, and counts. If the data reveals security concerns, highlight them."""

        fallback = f"Found {len(rows)} result(s). " + _format_results_fallback(rows, columns)
        answer = _call_llm(prompt, fallback)

    return {
        "query": query,
        "answer": answer,
        "sql_generated": sql,
        "result_count": len(rows),
        "alerts_referenced": len(rows),
    }


def _handle_general_query(query: str) -> dict:
    """Handle general SOC Q&A grounded on live data."""

    # Fetch current context
    with get_db() as conn:
        cur = conn.execute(
            "SELECT id, title, severity, attack_type, attacker_ip, llm_summary, "
            "confidence_score, verdict, timestamp FROM alerts ORDER BY timestamp DESC"
        )
        all_alerts = [dict(r) for r in cur.fetchall()]

        cur = conn.execute("SELECT COUNT(*) as c FROM logs")
        log_count = cur.fetchone()["c"]

        cur = conn.execute("SELECT COUNT(*) as c FROM responses WHERE action_type IN ('TEMP_BLOCK', 'PERM_BLOCK', 'BLOCK_IP')")
        block_count = cur.fetchone()["c"]

        cur = conn.execute("SELECT COUNT(*) as c FROM incidents WHERE status = 'ACTIVE'")
        active_incidents = cur.fetchone()["c"]

        cur = conn.execute("SELECT COUNT(*) as c FROM pending_approvals WHERE status = 'PENDING'")
        pending_approvals = cur.fetchone()["c"]

    # Build context for the LLM
    alerts_summary = json.dumps(all_alerts[:30], indent=2, default=str)

    prompt = f"""You are ShieldAI, an AI security analyst assistant embedded in a SOC dashboard. Answer the analyst's question using ONLY the data provided below. Do NOT invent facts.

CURRENT SOC DATA:
- Total Alerts: {len(all_alerts)}
- Total Logs Ingested: {log_count}
- Total IPs Blocked: {block_count}
- Active Incidents: {active_incidents}
- Pending Approvals: {pending_approvals}

RECENT ALERTS (latest 30):
{alerts_summary}

ANALYST QUESTION: {query}

Respond concisely and helpfully. If the data doesn't contain the answer, say so. Reference specific alert IDs and IPs where possible."""

    fallback_answer = _generate_fallback_answer(query, all_alerts, log_count, block_count,
                                                  active_incidents, pending_approvals)
    answer = _call_llm(prompt, fallback_answer)

    return {
        "query": query,
        "answer": answer,
        "alerts_referenced": len(all_alerts),
    }


def _generate_fallback_answer(query: str, alerts: list, log_count: int,
                               block_count: int, active_incidents: int,
                               pending_approvals: int) -> str:
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

    if "approval" in q or "pending" in q:
        return f"There are {pending_approvals} actions pending analyst approval."

    if "summary" in q or "overview" in q or "status" in q:
        types = {}
        for a in alerts:
            t = a.get("attack_type", "UNKNOWN")
            types[t] = types.get(t, 0) + 1
        breakdown = ", ".join(f"{v} {k}" for k, v in types.items())
        return (f"Current status: {len(alerts)} total alerts ({breakdown}), "
                f"{log_count} events ingested, {block_count} IPs blocked, "
                f"{active_incidents} active incidents, {pending_approvals} pending approvals.")

    return (f"I found {len(alerts)} alerts and {log_count} ingested events. "
            f"Could you be more specific about what you'd like to know?")


def _format_results_fallback(rows: list, columns: list) -> str:
    """Simple text formatting of query results."""
    if not rows:
        return "No data found."

    lines = []
    for row in rows[:10]:
        parts = [f"{k}: {v}" for k, v in row.items() if v is not None]
        lines.append(" | ".join(parts))

    result = "\n".join(lines)
    if len(rows) > 10:
        result += f"\n... and {len(rows) - 10} more rows."
    return result
