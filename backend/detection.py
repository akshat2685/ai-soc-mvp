from database import get_db
from ai_engine import generate_alert_summary, generate_attacker_report, generate_deterrence_email
from response import block_ip, throttle_ip, lock_account, send_deterrence_email
import json
import hashlib
import math

# ── Fallback static thresholds ──
CREDENTIAL_STUFFING_THRESHOLD = 5    # failed logins from same IP
OTP_ABUSE_THRESHOLD = 3              # OTP requests from same IP
BOT_REQUEST_THRESHOLD = 10           # requests with no/suspicious UA from same IP
ATO_FAILED_THEN_SUCCESS = 3          # failed logins before a success = account takeover
COUPON_ABUSE_THRESHOLD = 3           # coupon applications from same user
DISTRIBUTED_CREDENTIAL_STUFFING_THRESHOLD = 3 # distinct IPs targeting same user

def calculate_fingerprint(user_agent: str, device_id: str) -> str:
    ua = user_agent or ""
    did = device_id or ""
    if not ua and not did:
        return "unknown"
    return hashlib.sha256(f"{ua}|{did}".encode('utf-8')).hexdigest()[:16]

def get_adaptive_threshold(entity_field: str, entity_value: str, event_type: str, status: str = None, default_val: int = 5) -> int:
    """
    Computes baseline from rolling 24h window (grouped hourly) for entity.
    Returns mean + 3 * std_dev, or default_val as fallback if stats cannot be calculated.
    """
    if not entity_value:
        return default_val
        
    query = f"""
        SELECT COUNT(*) as cnt
        FROM logs
        WHERE {entity_field} = ? 
          AND event_type = ? 
    """
    params = [entity_value, event_type]
    if status is not None:
        query += " AND status = ?"
        params.append(status)
    query += " AND timestamp >= datetime('now', '-24 hours') GROUP BY strftime('%Y-%m-%d %H', timestamp)"
    
    with get_db() as conn:
        cur = conn.execute(query, params)
        rows = cur.fetchall()
        
    if not rows or len(rows) < 3:
        return default_val
        
    counts = [r['cnt'] for r in rows]
    mean = sum(counts) / len(counts)
    variance = sum((x - mean) ** 2 for x in counts) / len(counts)
    std_dev = math.sqrt(variance)
    
    threshold = math.ceil(mean + 3 * std_dev)
    return max(default_val, threshold)

def check_for_abuse(source_ip: str, user_id: str = None, device_id: str = None, user_agent: str = None):
    device_fingerprint = calculate_fingerprint(user_agent, device_id)

    # Populate device fingerprint for current log if not set
    with get_db() as conn:
        conn.execute(
            "UPDATE logs SET device_fingerprint = ? WHERE source_ip = ? AND timestamp >= datetime('now', '-5 seconds') AND device_fingerprint IS NULL",
            (device_fingerprint, source_ip)
        )
        conn.commit()

    with get_db() as conn:
        # ── Credential Stuffing by IP ──
        cur = conn.execute(
            "SELECT * FROM logs WHERE source_ip = ? AND event_type = 'login' AND status = 'failed' ORDER BY timestamp DESC",
            (source_ip,)
        )
        failed_logins = [dict(r) for r in cur.fetchall()]

        # ── Credential Stuffing by Device Fingerprint (IP Rotation Tracking) ──
        cur = conn.execute(
            "SELECT * FROM logs WHERE device_fingerprint = ? AND event_type = 'login' AND status = 'failed' ORDER BY timestamp DESC",
            (device_fingerprint,)
        )
        failed_logins_by_device = [dict(r) for r in cur.fetchall()]

        # ── OTP Abuse ──
        cur = conn.execute(
            "SELECT * FROM logs WHERE source_ip = ? AND event_type = 'otp_request' ORDER BY timestamp DESC",
            (source_ip,)
        )
        otp_requests = [dict(r) for r in cur.fetchall()]

        # ── Bot Detection (no user-agent or suspicious UA) ──
        cur = conn.execute(
            "SELECT * FROM logs WHERE source_ip = ? AND (user_agent IS NULL OR user_agent = '' OR user_agent LIKE '%bot%' OR user_agent LIKE '%curl%' OR user_agent LIKE '%python%' OR user_agent LIKE '%scanner%') ORDER BY timestamp DESC",
            (source_ip,)
        )
        bot_events = [dict(r) for r in cur.fetchall()]

        # ── Account Takeover (failed logins then a success from new device) ──
        cur = conn.execute(
            "SELECT * FROM logs WHERE source_ip = ? AND event_type = 'login' ORDER BY timestamp ASC",
            (source_ip,)
        )
        all_logins = [dict(r) for r in cur.fetchall()]

        # ── Business Logic / Coupon Abuse ──
        coupon_events = []
        if user_id:
            cur = conn.execute(
                "SELECT * FROM logs WHERE user_id = ? AND event_type = 'coupon_apply' ORDER BY timestamp DESC",
                (user_id,)
            )
            coupon_events = [dict(r) for r in cur.fetchall()]

        # ── Distributed Credential Stuffing (Same user targeted by multiple IPs) ──
        distributed_events = []
        if user_id:
            cur = conn.execute(
                "SELECT DISTINCT source_ip FROM logs WHERE user_id = ? AND event_type = 'login' AND status = 'failed' AND timestamp >= datetime('now', '-1 hour')",
                (user_id,)
            )
            distinct_ips = [r["source_ip"] for r in cur.fetchall()]
            if len(distinct_ips) >= get_adaptive_threshold("user_id", user_id, "login", "failed", DISTRIBUTED_CREDENTIAL_STUFFING_THRESHOLD):
                cur = conn.execute(
                    "SELECT * FROM logs WHERE user_id = ? AND event_type = 'login' AND status = 'failed' AND timestamp >= datetime('now', '-1 hour') ORDER BY timestamp DESC",
                    (user_id,)
                )
                distributed_events = [dict(r) for r in cur.fetchall()]

    # ── Fire detections using adaptive thresholds ──
    adaptive_cred_limit = get_adaptive_threshold("source_ip", source_ip, "login", "failed", CREDENTIAL_STUFFING_THRESHOLD)
    if len(failed_logins) >= adaptive_cred_limit:
        trigger_incident("Credential Stuffing", "CREDENTIAL_STUFFING", "HIGH", source_ip, failed_logins, device_fingerprint)

    adaptive_device_limit = get_adaptive_threshold("device_fingerprint", device_fingerprint, "login", "failed", CREDENTIAL_STUFFING_THRESHOLD)
    if len(failed_logins_by_device) >= adaptive_device_limit:
        trigger_incident("Credential Stuffing via rotated IPs", "CREDENTIAL_STUFFING", "HIGH", source_ip, failed_logins_by_device, device_fingerprint)

    adaptive_otp_limit = get_adaptive_threshold("source_ip", source_ip, "otp_request", None, OTP_ABUSE_THRESHOLD)
    if len(otp_requests) >= adaptive_otp_limit:
        trigger_incident("OTP Pumping / SMS Abuse", "OTP_ABUSE", "HIGH", source_ip, otp_requests, device_fingerprint)

    adaptive_bot_limit = get_adaptive_threshold("source_ip", source_ip, "page_view", None, BOT_REQUEST_THRESHOLD)
    if len(bot_events) >= adaptive_bot_limit:
        trigger_incident("Bot Activity Detected", "BOT_ACTIVITY", "MEDIUM", source_ip, bot_events, device_fingerprint)

    # ATO: check if there were N failed logins followed by a success
    failed_count = 0
    for login in all_logins:
        if login['status'] == 'failed':
            failed_count += 1
        elif login['status'] == 'success' and failed_count >= ATO_FAILED_THEN_SUCCESS:
            trigger_incident("Account Takeover", "ACCOUNT_TAKEOVER", "HIGH", source_ip, all_logins, device_fingerprint)
            break

    if coupon_events:
        adaptive_coupon_limit = get_adaptive_threshold("user_id", user_id, "coupon_apply", None, COUPON_ABUSE_THRESHOLD)
        if len(coupon_events) >= adaptive_coupon_limit:
            trigger_incident("Business Logic Abuse — Coupon Fraud", "BUSINESS_LOGIC", "MEDIUM", source_ip, coupon_events, device_fingerprint)

    if distributed_events:
        trigger_incident(f"Distributed Credential Stuffing targeting {user_id}", "DISTRIBUTED_CREDENTIAL_STUFFING", "HIGH", source_ip, distributed_events, device_fingerprint)

def correlate_alert_to_incident(alert_id: int, attacker_ip: str, user_ids: list, device_fingerprint: str, severity: str, title: str) -> int:
    with get_db() as conn:
        # Check active incidents in the last 30 minutes sharing same IP, user, or device fingerprint
        query = """
            SELECT id, title, severity FROM incidents 
            WHERE status = 'ACTIVE' 
              AND timestamp >= datetime('now', '-30 minutes')
              AND (correlation_key = ? OR correlation_key = ? OR correlation_key = ?)
        """
        cur = conn.execute(query, (attacker_ip, device_fingerprint, next((u for u in user_ids if u), None)))
        existing_incident = cur.fetchone()
        
        if existing_incident:
            incident_id = existing_incident["id"]
            conn.execute("UPDATE alerts SET incident_id = ? WHERE id = ?", (incident_id, alert_id))
            conn.execute("UPDATE responses SET incident_id = ? WHERE alert_id = ?", (incident_id, alert_id))
            if severity == "HIGH" and existing_incident["severity"] != "HIGH":
                conn.execute("UPDATE incidents SET severity = 'HIGH' WHERE id = ?", (incident_id,))
            conn.commit()
            return incident_id
        else:
            correlation_key = attacker_ip or device_fingerprint or next((u for u in user_ids if u), "unknown")
            cur = conn.execute(
                "INSERT INTO incidents (title, severity, status, correlation_key, llm_summary) VALUES (?, ?, ?, ?, ?)",
                (f"Incident: {title}", severity, "ACTIVE", correlation_key, f"Unified Incident containing alert related to {correlation_key}.")
            )
            incident_id = cur.lastrowid
            conn.execute("UPDATE alerts SET incident_id = ? WHERE id = ?", (incident_id, alert_id))
            conn.execute("UPDATE responses SET incident_id = ? WHERE alert_id = ?", (incident_id, alert_id))
            conn.commit()
            return incident_id

def trigger_incident(title: str, attack_type: str, severity: str, attacker_ip: str, events: list, device_fingerprint: str = None):
    # Prevent duplicate alerts for same IP + attack type in the last 10 minutes
    with get_db() as conn:
        cur = conn.execute(
            "SELECT id FROM alerts WHERE attacker_ip = ? AND attack_type = ? AND timestamp >= datetime('now', '-10 minutes')",
            (attacker_ip, attack_type)
        )
        if cur.fetchone():
            return

    evidence = {
        "source_ip": attacker_ip,
        "event_count": len(events),
        "attack_type": attack_type,
        "event_types": list(set(e.get('event_type', '') for e in events)),
        "user_agents": list(set(e.get('user_agent', '') for e in events if e.get('user_agent'))),
        "endpoints": list(set(e.get('endpoint', '') for e in events if e.get('endpoint'))),
        "user_ids": list(set(e.get('user_id', '') for e in events if e.get('user_id'))),
        "device_fingerprint": device_fingerprint
    }

    # 1. AI Triage
    summary = generate_alert_summary(title, evidence)

    # 2. Attacker Report
    report = generate_attacker_report(attacker_ip, events, attack_type)

    # 3. Deterrence Email
    email = generate_deterrence_email(attacker_ip, report, attack_type)

    # 4. Save Alert
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO alerts (title, severity, confidence, attack_type, evidence, attacker_ip, llm_summary, attacker_report, device_fingerprint) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (title, severity, "HIGH", attack_type, json.dumps(evidence), attacker_ip, summary, report, device_fingerprint)
        )
        conn.commit()
        alert_id = cur.lastrowid

    # 5. Incident Correlation
    incident_id = correlate_alert_to_incident(alert_id, attacker_ip, evidence.get("user_ids", []), device_fingerprint, severity, title)

    # 6. Autonomous Response
    if severity == "HIGH":
        block_ip(attacker_ip, alert_id)
        # Update response to link to incident
        with get_db() as conn:
            conn.execute("UPDATE responses SET incident_id = ? WHERE alert_id = ?", (incident_id, alert_id))
            conn.commit()
    else:
        throttle_ip(attacker_ip, alert_id)
        with get_db() as conn:
            conn.execute("UPDATE responses SET incident_id = ? WHERE alert_id = ?", (incident_id, alert_id))
            conn.commit()

    if attack_type == "ACCOUNT_TAKEOVER":
        for uid in evidence.get("user_ids", []):
            if uid:
                lock_account(uid, alert_id)
                with get_db() as conn:
                    conn.execute("UPDATE responses SET incident_id = ? WHERE alert_id = ?", (incident_id, alert_id))
                    conn.commit()

    send_deterrence_email(attacker_ip, email, alert_id)
    with get_db() as conn:
        conn.execute("UPDATE responses SET incident_id = ? WHERE alert_id = ?", (incident_id, alert_id))
        conn.commit()

    # 7. Threat Intelligence Enrichment
    try:
        from threat_intel import enrich_ip
        enrich_ip(attacker_ip)
    except Exception as e:
        print(f"[DETECTION] Threat intel enrichment failed: {e}")

    # 8. Broadcast via WebSocket
    from main import broadcast_event
    broadcast_event({
        "type": "new_alert",
        "alert": {
            "id": alert_id,
            "incident_id": incident_id,
            "title": title,
            "severity": severity,
            "attack_type": attack_type,
            "attacker_ip": attacker_ip,
            "llm_summary": summary,
        }
    })
