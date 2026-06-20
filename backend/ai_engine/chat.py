from .core import call_llm

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
    result = call_llm(prompt, fallback)

    # Clean up — extract just the SQL
    result = result.strip()
    if result.startswith("```"):
        lines = result.split("\n")
        result = "\n".join(l for l in lines if not l.startswith("```"))
    result = result.strip().rstrip(";")

    return result
