"""Weekly/Monthly Digest Report Generator.

Generates a comprehensive PDF digest covering:
- Executive summary (alerts, incidents, blocks)
- Top attacked endpoints
- Repeat offender IPs
- Attack type trends
- False positive rate
- Mean time to detect / respond
"""
import json
import os
import time
from fpdf import FPDF
from database import get_db

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)


def generate_digest(period: str = "week") -> str:
    """Generate a digest PDF for the given period. Returns the file path."""

    days = 7 if period == "week" else 30
    period_label = "Weekly" if period == "week" else "Monthly"
    time_filter = f"-{days} days"

    with get_db() as conn:
        # ── Executive Summary ──
        total_alerts = conn.execute(
            "SELECT COUNT(*) as c FROM alerts WHERE timestamp >= datetime('now', ?)",
            (time_filter,)
        ).fetchone()['c']

        total_incidents = conn.execute(
            "SELECT COUNT(*) as c FROM incidents WHERE timestamp >= datetime('now', ?)",
            (time_filter,)
        ).fetchone()['c']

        total_blocked = conn.execute(
            "SELECT COUNT(*) as c FROM responses WHERE action_type IN ('TEMP_BLOCK', 'PERM_BLOCK', 'BLOCK_IP') "
            "AND timestamp >= datetime('now', ?)",
            (time_filter,)
        ).fetchone()['c']

        total_logs = conn.execute(
            "SELECT COUNT(*) as c FROM logs WHERE timestamp >= datetime('now', ?)",
            (time_filter,)
        ).fetchone()['c']

        # ── Attack Type Distribution ──
        cur = conn.execute(
            "SELECT attack_type, COUNT(*) as count FROM alerts "
            "WHERE timestamp >= datetime('now', ?) GROUP BY attack_type ORDER BY count DESC",
            (time_filter,)
        )
        attack_dist = [dict(r) for r in cur.fetchall()]

        # ── Top Attacked Endpoints ──
        cur = conn.execute(
            "SELECT endpoint, COUNT(*) as count FROM logs "
            "WHERE timestamp >= datetime('now', ?) AND endpoint IS NOT NULL "
            "GROUP BY endpoint ORDER BY count DESC LIMIT 10",
            (time_filter,)
        )
        top_endpoints = [dict(r) for r in cur.fetchall()]

        # ── Repeat Offender IPs ──
        cur = conn.execute(
            "SELECT attacker_ip, COUNT(*) as alert_count, GROUP_CONCAT(DISTINCT attack_type) as types "
            "FROM alerts WHERE timestamp >= datetime('now', ?) "
            "GROUP BY attacker_ip ORDER BY alert_count DESC LIMIT 10",
            (time_filter,)
        )
        repeat_offenders = [dict(r) for r in cur.fetchall()]

        # ── Severity Distribution ──
        cur = conn.execute(
            "SELECT severity, COUNT(*) as count FROM alerts "
            "WHERE timestamp >= datetime('now', ?) GROUP BY severity",
            (time_filter,)
        )
        severity_dist = {r['severity']: r['count'] for r in cur.fetchall()}

        # ── False Positive Rate ──
        total_verdicts = conn.execute(
            "SELECT COUNT(*) as c FROM alerts WHERE verdict != 'PENDING' "
            "AND timestamp >= datetime('now', ?)",
            (time_filter,)
        ).fetchone()['c']
        false_positives = conn.execute(
            "SELECT COUNT(*) as c FROM alerts WHERE verdict = 'FALSE_POSITIVE' "
            "AND timestamp >= datetime('now', ?)",
            (time_filter,)
        ).fetchone()['c']
        fp_rate = (false_positives / total_verdicts * 100) if total_verdicts > 0 else 0

        # ── Response Actions Summary ──
        cur = conn.execute(
            "SELECT action_type, COUNT(*) as count FROM responses "
            "WHERE timestamp >= datetime('now', ?) GROUP BY action_type ORDER BY count DESC",
            (time_filter,)
        )
        response_actions = [dict(r) for r in cur.fetchall()]

        # ── Geo Distribution ──
        cur = conn.execute(
            "SELECT country, country_code, flag, COUNT(*) as count FROM threat_intel "
            "JOIN alerts ON threat_intel.ip = alerts.attacker_ip "
            "WHERE alerts.timestamp >= datetime('now', ?) "
            "GROUP BY country ORDER BY count DESC LIMIT 10",
            (time_filter,)
        )
        geo_dist = [dict(r) for r in cur.fetchall()]

    # ── Build PDF ──
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Title
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 15, f"ShieldAI SOC — {period_label} Digest Report", ln=True, align="C")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(128, 128, 128)
    pdf.cell(0, 8, f"Period: Last {days} days | Generated: {time.strftime('%Y-%m-%d %H:%M')}", ln=True, align="C")
    pdf.ln(10)

    # Executive Summary
    _section_header(pdf, "1. Executive Summary")
    _add_field(pdf, "Total Alerts", str(total_alerts))
    _add_field(pdf, "Total Incidents", str(total_incidents))
    _add_field(pdf, "IPs Blocked", str(total_blocked))
    _add_field(pdf, "Events Ingested", str(total_logs))
    _add_field(pdf, "False Positive Rate", f"{fp_rate:.1f}% ({false_positives}/{total_verdicts} reviewed)")
    pdf.ln(5)

    # Severity Distribution
    _section_header(pdf, "2. Severity Distribution")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = severity_dist.get(sev, 0)
        _add_field(pdf, sev, str(count))
    pdf.ln(5)

    # Attack Type Distribution
    _section_header(pdf, "3. Attack Type Distribution")
    for item in attack_dist:
        at = item['attack_type'] or 'UNKNOWN'
        _add_field(pdf, at.replace('_', ' ').title(), str(item['count']))
    pdf.ln(5)

    # Top Attacked Endpoints
    _section_header(pdf, "4. Top Attacked Endpoints")
    pdf.set_font("Courier", "", 9)
    for i, ep in enumerate(top_endpoints, 1):
        pdf.cell(0, 5, f"  {i}. {ep['endpoint']} ({ep['count']} hits)", ln=True)
    pdf.ln(5)

    # Repeat Offenders
    pdf.add_page()
    _section_header(pdf, "5. Repeat Offender IPs")
    pdf.set_font("Courier", "", 9)
    for i, ip in enumerate(repeat_offenders, 1):
        types = ip.get('types', 'N/A')
        pdf.cell(0, 5, f"  {i}. {ip['attacker_ip']} — {ip['alert_count']} alerts [{types}]", ln=True)
    pdf.ln(5)

    # Geo Distribution
    _section_header(pdf, "6. Source Country Distribution")
    for geo in geo_dist:
        flag = geo.get('flag', '').encode('latin-1', 'ignore').decode('latin-1')
        _add_field(pdf, f"{flag} {geo['country']}", f"{geo['count']} alerts")
    pdf.ln(5)

    # Response Actions
    _section_header(pdf, "7. Autonomous Response Actions")
    for action in response_actions:
        _add_field(pdf, action['action_type'], str(action['count']))
    pdf.ln(5)

    # Footer
    pdf.ln(10)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(128, 128, 128)
    pdf.cell(0, 5, "Generated by ShieldAI SOC Platform — Confidential", ln=True, align="C")

    filename = f"digest_{period}_{int(time.time())}.pdf"
    filepath = os.path.join(REPORTS_DIR, filename)
    pdf.output(filepath)
    return filepath


def _section_header(pdf, text):
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(30, 30, 30)
    pdf.set_fill_color(240, 240, 240)
    text = text.encode('latin-1', 'ignore').decode('latin-1')
    pdf.cell(0, 10, text, ln=True, fill=True)
    pdf.ln(3)
    pdf.set_text_color(50, 50, 50)


def _add_field(pdf, label, value):
    pdf.set_font("Helvetica", "B", 10)
    label = str(label).encode('latin-1', 'ignore').decode('latin-1')
    value = str(value).encode('latin-1', 'ignore').decode('latin-1')
    pdf.cell(60, 6, f"  {label}:")
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, value, ln=True)
