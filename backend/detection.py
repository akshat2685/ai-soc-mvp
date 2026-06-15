"""Detection Engine — orchestrates modular detectors and triggers incidents.

This module now delegates to individual detector classes in detectors/ while
maintaining the original API surface (check_for_abuse, calculate_fingerprint).
"""
from database import get_db
from ai_engine import generate_alert_summary, generate_attacker_report, generate_deterrence_email
from response import ResponseEngine
import json
import hashlib

# ── Device Fingerprinting (enhanced) ──

def calculate_fingerprint(user_agent: str, device_id: str, headers: dict = None) -> str:
    """Generate a device fingerprint from UA, device ID, and header patterns.
    Includes header ordering signature (JA3-like for HTTP) to catch tool reuse."""
    ua = user_agent or ""
    did = device_id or ""
    header_str = ""
    header_order_sig = ""

    if headers and isinstance(headers, dict):
        # Filter out transient / dynamic headers to remain deterministic
        ignore_headers = {'cookie', 'authorization', 'host', 'content-length',
                          'date', 'connection', 'content-type'}
        filtered = {k.lower(): v for k, v in headers.items()
                     if k.lower() not in ignore_headers}
        sorted_hdrs = sorted([f"{k}:{v}" for k, v in filtered.items()])
        header_str = "|".join(sorted_hdrs)

        # Header ordering signature — the order headers are sent is a fingerprint
        # of the HTTP library/tool being used
        header_order_sig = ",".join(k.lower() for k in headers.keys()
                                    if k.lower() not in ignore_headers)

    if not ua and not did and not header_str:
        return "unknown"

    raw = f"{ua}|{did}|{header_str}|{header_order_sig}"
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()[:16]


# ── Main Detection Entry Point ──

_response_engine = ResponseEngine()

def check_for_abuse(source_ip: str, user_id: str = None, device_id: str = None,
                    user_agent: str = None, headers: dict = None, background_tasks = None):
    """Main entry point called from /ingest. Runs all modular detectors."""
    from detectors import run_all_detectors

    results = run_all_detectors(source_ip, user_id, device_id, user_agent, headers)

    # Trigger incidents for each detection result
    for result in results:
        trigger_incident(
            title=result.title,
            attack_type=result.attack_type,
            severity=result.severity,
            attacker_ip=result.source_ip,
            events=result.events,
            device_fingerprint=result.device_fingerprint,
            confidence_score=result.confidence_score,
            evidence_citations=result.evidence_citations,
            background_tasks=background_tasks
        )


# ── Incident Correlation ──

def correlate_alert_to_incident(alert_id: int, attacker_ip: str, user_ids: list,
                                 device_fingerprint: str, severity: str, title: str) -> int:
    """Correlate an alert to an existing incident or create a new one."""
    with get_db() as conn:
        incident_id = None

        # 1. Search for recent alerts sharing IP (last 30 minutes)
        if attacker_ip:
            cur = conn.execute(
                "SELECT incident_id FROM alerts WHERE attacker_ip = ? AND incident_id IS NOT NULL "
                "AND timestamp >= datetime('now', '-30 minutes') LIMIT 1",
                (attacker_ip,)
            )
            row = cur.fetchone()
            if row:
                incident_id = row["incident_id"]

        # 2. Search for recent alerts sharing device fingerprint
        if not incident_id and device_fingerprint and device_fingerprint != "unknown":
            cur = conn.execute(
                "SELECT incident_id FROM alerts WHERE device_fingerprint = ? AND incident_id IS NOT NULL "
                "AND timestamp >= datetime('now', '-30 minutes') LIMIT 1",
                (device_fingerprint,)
            )
            row = cur.fetchone()
            if row:
                incident_id = row["incident_id"]

        # 3. Search for recent alerts targeting the same user IDs
        if not incident_id and user_ids:
            for uid in user_ids:
                if uid:
                    cur = conn.execute(
                        "SELECT incident_id FROM alerts WHERE evidence LIKE ? "
                        "AND incident_id IS NOT NULL AND timestamp >= datetime('now', '-30 minutes') LIMIT 1",
                        (f"%{uid}%",)
                    )
                    row = cur.fetchone()
                    if row:
                        incident_id = row["incident_id"]
                        break

        if incident_id:
            # Check if incident is still ACTIVE
            cur = conn.execute("SELECT status, severity FROM incidents WHERE id = ?", (incident_id,))
            inc = cur.fetchone()
            if inc and inc["status"] == "ACTIVE":
                conn.execute("UPDATE alerts SET incident_id = ? WHERE id = ?", (incident_id, alert_id))
                conn.execute("UPDATE responses SET incident_id = ? WHERE alert_id = ?", (incident_id, alert_id))
                if severity in ("HIGH", "CRITICAL") and inc["severity"] not in ("HIGH", "CRITICAL"):
                    conn.execute("UPDATE incidents SET severity = ? WHERE id = ?", (severity, incident_id))
                conn.commit()
                return incident_id

        # Create a new incident if none found or existing one is resolved
        correlation_key = attacker_ip or device_fingerprint or next((u for u in user_ids if u), "unknown")
        cur = conn.execute(
            "INSERT INTO incidents (title, severity, status, correlation_key, llm_summary) VALUES (?, ?, ?, ?, ?)",
            (f"Incident: {title}", severity, "ACTIVE", correlation_key,
             f"Unified Incident containing alert related to {correlation_key}.")
        )
        incident_id = cur.lastrowid
        conn.execute("UPDATE alerts SET incident_id = ? WHERE id = ?", (incident_id, alert_id))
        conn.execute("UPDATE responses SET incident_id = ? WHERE alert_id = ?", (incident_id, alert_id))
        conn.commit()
        return incident_id


# ── Trigger Incident ──

def trigger_incident(title: str, attack_type: str, severity: str, attacker_ip: str,
                     events: list, device_fingerprint: str = None,
                     confidence_score: int = 80, evidence_citations: list = None, background_tasks = None):
    """Process a detection result: Save alert → respond immediately → generate reports in background."""

    evidence = {
        "source_ip": attacker_ip,
        "event_count": len(events),
        "attack_type": attack_type,
        "event_types": list(set(e.get('event_type', '') for e in events)),
        "user_agents": list(set(e.get('user_agent', '') for e in events if e.get('user_agent'))),
        "endpoints": list(set(e.get('endpoint', '') for e in events if e.get('endpoint'))),
        "user_ids": list(set(e.get('user_id', '') for e in events if e.get('user_id'))),
        "device_fingerprint": device_fingerprint,
        "confidence_score": confidence_score,
    }

    # 1. Save Alert immediately with placeholder text
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO alerts (title, severity, confidence, confidence_score, attack_type, "
            "evidence, evidence_citations, attacker_ip, llm_summary, attacker_report, device_fingerprint) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (title, severity, "HIGH", confidence_score, attack_type,
             json.dumps(evidence), json.dumps(evidence_citations or []),
             attacker_ip, "Generating summary...", "Generating report...", device_fingerprint)
        )
        conn.commit()
        alert_id = cur.lastrowid

    # 2. Incident Correlation
    incident_id = correlate_alert_to_incident(
        alert_id, attacker_ip, evidence.get("user_ids", []),
        device_fingerprint, severity, title
    )

    # 3. Tiered Autonomous Response (IMMEDIATE)
    _response_engine.execute_tiered_response(
        severity=severity,
        confidence_score=confidence_score,
        target_ip=attacker_ip,
        alert_id=alert_id,
        incident_id=incident_id,
        attack_type=attack_type,
        evidence=evidence,
    )

    # 4. Handle ATO-specific actions (IMMEDIATE)
    if attack_type == "ACCOUNT_TAKEOVER":
        for uid in evidence.get("user_ids", []):
            if uid:
                _response_engine.lock_account(uid, alert_id, incident_id, evidence)

    # 5. Broadcast via WebSocket immediately
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
            "llm_summary": "Generating summary...",
            "confidence_score": confidence_score,
        }
    })

    # 6. Background Task for LLM and slow operations
    def _generate_reports_task():
        # LLM Triage
        summary = generate_alert_summary(title, evidence, events[:20])
        report = generate_attacker_report(attacker_ip, events, attack_type)
        email = generate_deterrence_email(attacker_ip, report, attack_type)

        with get_db() as conn:
            conn.execute(
                "UPDATE alerts SET llm_summary = ?, attacker_report = ? WHERE id = ?",
                (summary, report, alert_id)
            )
            conn.commit()

        _response_engine.draft_deterrence_email(attacker_ip, email, alert_id, incident_id)

        try:
            from threat_intel import enrich_ip
            enrich_ip(attacker_ip)
        except Exception as e:
            print(f"[DETECTION] Threat intel enrichment failed: {e}")

        # Broadcast update to UI
        broadcast_event({
            "type": "alert_updated",
            "alert_id": alert_id,
            "llm_summary": summary
        })

    if background_tasks:
        background_tasks.add_task(_generate_reports_task)
    else:
        _generate_reports_task()


# ── Background Baseline Updater ──

def update_entity_baselines():
    """Recompute entity baselines from the last 7 days of logs.
    Should be called periodically (e.g., every hour)."""
    import math

    entities_to_track = [
        ("source_ip", "event_type"),
        ("user_id", "event_type"),
        ("device_fingerprint", "event_type"),
    ]

    with get_db() as conn:
        for entity_field, group_field in entities_to_track:
            # Get distinct entities with activity in last 7 days
            cur = conn.execute(
                f"SELECT DISTINCT {entity_field}, {group_field} FROM logs "
                f"WHERE timestamp >= datetime('now', '-7 days') AND {entity_field} IS NOT NULL"
            )
            entity_pairs = [(r[entity_field], r[group_field]) for r in cur.fetchall()]

            for entity_value, event_type in entity_pairs:
                if not entity_value:
                    continue

                # Compute hourly counts grouped by hour_of_day and day_of_week
                cur = conn.execute(
                    f"SELECT CAST(strftime('%H', timestamp) AS INTEGER) as hour, "
                    f"CAST(strftime('%w', timestamp) AS INTEGER) as dow, "
                    f"COUNT(*) as cnt "
                    f"FROM logs WHERE {entity_field} = ? AND event_type = ? "
                    f"AND timestamp >= datetime('now', '-7 days') "
                    f"GROUP BY hour, dow",
                    (entity_value, event_type)
                )
                rows = cur.fetchall()
                for row in rows:
                    hour = row['hour']
                    dow = row['dow']
                    count = row['cnt']
                    # Simple single-sample update; over time converges to rolling avg
                    conn.execute(
                        "INSERT OR REPLACE INTO entity_baselines "
                        "(entity_type, entity_value, event_type, hour_of_day, day_of_week, "
                        "avg_count, std_dev, sample_count, last_updated) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))",
                        (entity_field, entity_value, event_type, hour, dow,
                         float(count), float(count) * 0.3, 1)  # Initial std_dev = 30% of mean
                    )

        conn.commit()
    print("[BASELINE] Entity baselines updated.")
