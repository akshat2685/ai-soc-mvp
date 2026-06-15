"""Cross-Signal Correlation Engine — escalates severity when multiple attack types 
are detected from the same entity cluster within a configurable time window."""
import json
from database import get_db


class CorrelationEngine:
    """Checks correlation rules after detectors fire. If multiple attack types
    from the same IP/user/fingerprint match a rule, escalates severity."""

    def run(self, source_ip: str, user_id: str = None, device_fingerprint: str = None):
        """Check all enabled correlation rules against recent alerts."""
        with get_db() as conn:
            cur = conn.execute("SELECT * FROM correlation_rules WHERE enabled = 1")
            rules = [dict(r) for r in cur.fetchall()]

        for rule in rules:
            self._evaluate_rule(rule, source_ip, user_id, device_fingerprint)

    def _evaluate_rule(self, rule: dict, source_ip: str, user_id: str = None,
                       device_fingerprint: str = None):
        """Evaluate a single correlation rule."""
        required_types = json.loads(rule['attack_types'])
        window = rule['time_window_minutes']
        min_alerts = rule['min_alerts']
        escalate_to = rule['escalate_severity']

        with get_db() as conn:
            # Find recent alerts matching any of the required attack types for this entity
            type_placeholders = ",".join("?" for _ in required_types)
            
            # Search by IP
            matching_alerts = []
            if source_ip:
                cur = conn.execute(
                    f"SELECT * FROM alerts WHERE attacker_ip = ? "
                    f"AND attack_type IN ({type_placeholders}) "
                    f"AND timestamp >= datetime('now', '-{window} minutes') "
                    f"ORDER BY timestamp DESC",
                    (source_ip, *required_types)
                )
                matching_alerts.extend([dict(r) for r in cur.fetchall()])

            # Also search by fingerprint
            if device_fingerprint and device_fingerprint != "unknown":
                cur = conn.execute(
                    f"SELECT * FROM alerts WHERE device_fingerprint = ? "
                    f"AND attack_type IN ({type_placeholders}) "
                    f"AND timestamp >= datetime('now', '-{window} minutes') "
                    f"AND id NOT IN ({','.join(str(a['id']) for a in matching_alerts) or '0'})"
                    f"ORDER BY timestamp DESC",
                    (device_fingerprint, *required_types)
                )
                matching_alerts.extend([dict(r) for r in cur.fetchall()])

            # Check if we have enough distinct attack types
            matched_types = set(a['attack_type'] for a in matching_alerts)
            if len(matched_types) >= min_alerts and len(matched_types) >= 2:
                # Escalate all matching alerts
                self._escalate(conn, matching_alerts, rule, escalate_to)

    def _escalate(self, conn, alerts: list, rule: dict, escalate_to: str):
        """Escalate matching alerts to higher severity and update incident."""
        alert_ids = [a['id'] for a in alerts]
        incident_ids = set(a.get('incident_id') for a in alerts if a.get('incident_id'))

        # Escalate alert severities
        for alert_id in alert_ids:
            conn.execute(
                "UPDATE alerts SET severity = ? WHERE id = ? AND severity != ?",
                (escalate_to, alert_id, escalate_to)
            )

        # Escalate incident severities
        for inc_id in incident_ids:
            conn.execute(
                "UPDATE incidents SET severity = ?, llm_summary = llm_summary || ? WHERE id = ?",
                (escalate_to,
                 f"\n\n⚠️ ESCALATED by correlation rule '{rule['name']}': "
                 f"Multiple attack types detected from same entity.",
                 inc_id)
            )

        conn.commit()
        matched_types = set(a['attack_type'] for a in alerts)
        print(f"[CORRELATION] Rule '{rule['name']}' triggered — "
              f"escalated {len(alert_ids)} alerts to {escalate_to}. "
              f"Attack types: {matched_types}")
