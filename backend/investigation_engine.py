import json
from datetime import datetime, timedelta
from database import get_db
from ai_engine import _call_llm
from mitre_engine import get_mitre_mapping
from threat_intel_engine import check_cve_kev
try:
    from rag_engine import search_knowledge
except ImportError:
    search_knowledge = None

def serialize_datetime(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")


def run_investigation(alert_id: int) -> dict:
    """
    Executes a 10-step automated investigation pipeline for a given alert ID.
    Returns the investigation report dictionary and writes it to the database.
    """
    print(f"[INVESTIGATION] Starting investigation for Alert ID: {alert_id}")
    
    # Fetch the alert details
    with get_db() as conn:
        cur = conn.execute(
            "SELECT id, timestamp, title, severity, confidence, confidence_score, "
            "attack_type, evidence, attacker_ip, incident_id, device_fingerprint "
            "FROM alerts WHERE id = ?", (alert_id,)
        )
        alert_row = cur.fetchone()
        if not alert_row:
            print(f"[INVESTIGATION] Alert ID {alert_id} not found.")
            return {"error": f"Alert {alert_id} not found"}
        
        alert = dict(alert_row)
        evidence = json.loads(alert.get("evidence") or "{}")
        attacker_ip = alert.get("attacker_ip")
        device_fp = alert.get("device_fingerprint")
        alert_ts = alert.get("timestamp")
        incident_id = alert.get("incident_id")
        attack_type = alert.get("attack_type")
        mitre_map = get_mitre_mapping(attack_type)
        
        # Parse timestamp safely
        if isinstance(alert_ts, datetime):
            alert_dt = alert_ts
        else:
            try:
                alert_dt = datetime.strptime(alert_ts.split(".")[0], "%Y-%m-%d %H:%M:%S")
            except ValueError:
                try:
                    alert_dt = datetime.strptime(alert_ts, "%Y-%m-%d %T")
                except Exception:
                    alert_dt = datetime.now()

        # Step 1: Collect all related logs (+/- 30 mins)
        start_dt = alert_dt - timedelta(minutes=30)
        end_dt = alert_dt + timedelta(minutes=30)
        
        user_ids = evidence.get("user_ids", [])
        if not user_ids and evidence.get("user_id"):
            user_ids = [evidence.get("user_id")]
        
        log_query = """
            SELECT id, timestamp, event_type, source_ip, user_id, status, 
                   device_id, user_agent, endpoint, method, device_fingerprint 
            FROM logs 
            WHERE timestamp BETWEEN ? AND ? 
              AND (source_ip = ? OR device_fingerprint = ? 
        """
        params = [start_dt.strftime("%Y-%m-%d %H:%M:%S"), end_dt.strftime("%Y-%m-%d %H:%M:%S"), attacker_ip, device_fp]
        
        if user_ids:
            log_query += " OR user_id IN (" + ",".join("?" for _ in user_ids) + ")"
            params.extend(user_ids)
        
        log_query += ") ORDER BY timestamp ASC"
        
        cur = conn.execute(log_query, params)
        related_logs = [dict(row) for row in cur.fetchall()]
        
        # Step 2: Collect asset inventory info
        collected_assets = []
        if attacker_ip:
            cur = conn.execute("SELECT ip_address, hostname, owner, os, criticality FROM assets WHERE ip_address = ?", (attacker_ip,))
            row = cur.fetchone()
            if row:
                collected_assets.append(dict(row))
        # Also look for assets targeted in logs or evidence
        targeted_ips = list(set(log.get("source_ip") for log in related_logs if log.get("source_ip")))
        if evidence.get("target_ip") and evidence.get("target_ip") not in targeted_ips:
            targeted_ips.append(evidence.get("target_ip"))
            
        for ip in targeted_ips:
            if ip != attacker_ip or ip == evidence.get("target_ip"):
                cur = conn.execute("SELECT ip_address, hostname, owner, os, criticality FROM assets WHERE ip_address = ?", (ip,))
                row = cur.fetchone()
                if row and dict(row) not in collected_assets:
                    collected_assets.append(dict(row))

        # Step 3: Collect vulnerability records
        collected_vulns = []
        for ip in targeted_ips:
            cur = conn.execute("SELECT ip_address, cve_id, severity, title, description, tool_source FROM vulnerabilities WHERE ip_address = ?", (ip,))
            for row in cur.fetchall():
                collected_vulns.append(dict(row))

        # Check if any collected vulnerability is in the CISA KEV catalog
        kev_matches = []
        for vuln in collected_vulns:
            cve_id = vuln.get("cve_id")
            if cve_id:
                kev_info = check_cve_kev(cve_id)
                if kev_info and kev_info not in kev_matches:
                    kev_matches.append(kev_info)

        # Step 4: Collect user activity history (last 7 days)
        user_history = {}
        seven_days_ago = (alert_dt - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
        for uid in user_ids:
            if uid:
                cur = conn.execute(
                    "SELECT status, COUNT(*) as count FROM logs "
                    "WHERE user_id = ? AND timestamp >= ? GROUP BY status", 
                    (uid, seven_days_ago)
                )
                stats = {row["status"]: row["count"] for row in cur.fetchall()}
                user_history[uid] = stats

        # Step 5: Collect previous incidents (last 7 days)
        previous_incidents = []
        cur = conn.execute(
            "SELECT id, timestamp, title, severity, verdict, correlation_key "
            "FROM incidents WHERE timestamp >= ? AND status != 'RESOLVED'",
            (seven_days_ago,)
        )
        for row in cur.fetchall():
            inc = dict(row)
            # Match correlation keys or similar attributes
            corr_key = inc.get("correlation_key", "")
            if (attacker_ip and attacker_ip in corr_key) or (device_fp and device_fp in corr_key):
                previous_incidents.append(inc)
            else:
                # Check if incident contains alerts with our target users
                cur_al = conn.execute(
                    "SELECT 1 FROM alerts WHERE incident_id = ? AND (attacker_ip = ? OR device_fingerprint = ?)",
                    (inc["id"], attacker_ip, device_fp)
                )
                if cur_al.fetchone():
                    previous_incidents.append(inc)

        # Step 5b: Historical Context Memory (Last 6 months)
        historical_context = ""
        six_months_ago = (alert_dt - timedelta(days=180)).strftime("%Y-%m-%d %H:%M:%S")
        
        # Check if this exact attack type was seen for this IP or User in the past 6 months
        query_hist = """
            SELECT COUNT(*) as hist_count, 
                   SUM(CASE WHEN verdict = 'FALSE_POSITIVE' THEN 1 ELSE 0 END) as fp_count 
            FROM alerts 
            WHERE attack_type = ? AND timestamp >= ? AND (attacker_ip = ?
        """
        params_hist = [attack_type, six_months_ago, attacker_ip]
        if user_ids:
            query_hist += " OR evidence LIKE ?"
            params_hist.append(f"%{user_ids[0]}%")
        query_hist += ")"
        
        cur_hist = conn.execute(query_hist, tuple(params_hist))
        hist_row = cur_hist.fetchone()
        
        hist_count = hist_row["hist_count"] if hist_row else 0
        fp_count = hist_row["fp_count"] if hist_row else 0
        
        if hist_count > 0:
            fp_rate = (fp_count / hist_count) * 100 if hist_count > 0 else 0
            historical_context = f"This exact alert ({attack_type}) triggered {hist_count} times in the last 6 months for this host/user. "
            if fp_rate > 70:
                historical_context += f"Behavior historically matches administrator/benign activity (Marked as False Positive {fp_count} times). Risk severely reduced."
            else:
                historical_context += f"Marked as False Positive {fp_count} times."

        # Step 6: Correlate evidence
        # Fetch threat intel
        threat_intel_record = None
        if attacker_ip:
            cur = conn.execute("SELECT ip, country, isp, abuse_score, usage_type FROM threat_intel WHERE ip = ?", (attacker_ip,))
            row = cur.fetchone()
            if row:
                threat_intel_record = dict(row)

        correlation_reasons = []
        if threat_intel_record and threat_intel_record.get("abuse_score", 0) > 50:
            correlation_reasons.append(f"Attacker IP {attacker_ip} has a high reputation abuse score of {threat_intel_record['abuse_score']}.")
        
        # Check if same device fingerprint was used by multiple IPs
        if device_fp and device_fp != "unknown":
            cur = conn.execute(
                "SELECT COUNT(DISTINCT source_ip) as ip_count FROM logs WHERE device_fingerprint = ? AND timestamp >= ?",
                (device_fp, seven_days_ago)
            )
            ip_count = cur.fetchone()["ip_count"]
            if ip_count > 1:
                correlation_reasons.append(f"Device fingerprint {device_fp} was seen across {ip_count} distinct IP addresses (highly anomalous/proxy rotation).")
        
        # Check if same IP targeted multiple users
        if attacker_ip:
            cur = conn.execute(
                "SELECT COUNT(DISTINCT user_id) as user_count FROM logs WHERE source_ip = ? AND timestamp >= ? AND user_id IS NOT NULL",
                (attacker_ip, seven_days_ago)
            )
            user_count = cur.fetchone()["user_count"]
            if user_count > 3:
                correlation_reasons.append(f"Attacker IP {attacker_ip} targeted {user_count} distinct user accounts in the last 7 days.")

        # Check if there are active KEV matches on target assets
        for km in kev_matches:
            correlation_reasons.append(f"Target vulnerability {km['cve_id']} ({km['vulnerability_name']}) is listed in CISA KEV (Known Exploited Vulnerabilities) catalog.")

        correlation_summary = "\n".join(correlation_reasons) if correlation_reasons else "No high-confidence multi-vector correlations detected."

        # Step 7: Generate Attack Timeline
        # Sort logs chronologically to generate timeline
        timeline_events = []
        for log in related_logs:
            timeline_events.append({
                "time": log.get("timestamp"),
                "event": f"Log: {log.get('event_type')} from IP {log.get('source_ip')} targeting User {log.get('user_id')} (Status: {log.get('status')})",
                "type": "log"
            })
        
        # Add the alert trigger itself
        timeline_events.append({
            "time": alert_ts,
            "event": f"ALERT TRIGGERED: {alert.get('title')} ({attack_type}) - Severity: {alert.get('severity')}",
            "type": "alert"
        })
        
        timeline_events.sort(key=lambda x: x["time"])
        timeline_md = "### Attack Timeline\n\n"
        for evt in timeline_events:
            prefix = "[ALERT]" if evt["type"] == "alert" else "[INFO]"
            timeline_md += f"{prefix} **{evt['time']}** - {evt['event']}\n"

        # Step 8: Calculate Confidence Score
        # Start with default alert confidence
        conf_score = alert.get("confidence_score", 80)
        reasons = [f"Base alert confidence: {conf_score}"]
        
        # Adjust based on threat intel
        if threat_intel_record:
            abuse = threat_intel_record.get("abuse_score", 0)
            if abuse > 75:
                conf_score += 15
                reasons.append("Attacker IP has critical abuse score (>75) (+15)")
            elif abuse > 40:
                conf_score += 10
                reasons.append("Attacker IP has elevated abuse score (+10)")
                
        # Adjust based on asset criticality & exposure
        critical_asset_targeted = any(asset.get("criticality") == "HIGH" for asset in collected_assets)
        contains_customer_data = any(asset.get("contains_customer_data") == 1 for asset in collected_assets)
        internet_facing = any(asset.get("internet_facing") == 1 for asset in collected_assets)
        
        if critical_asset_targeted:
            conf_score += 10
            reasons.append("Target asset has HIGH criticality (+10)")
        if contains_customer_data:
            conf_score += 15
            reasons.append("Target asset contains customer data (+15)")
        if internet_facing:
            conf_score += 5
            reasons.append("Target asset is internet-facing (+5)")

        # Adjust based on matching vulnerabilities
        if collected_vulns:
            conf_score += 15
            reasons.append("Attacker targeted IPs matching known CVE vulnerability records (+15)")
            
        # Adjust based on CISA KEV catalog matches
        if kev_matches:
            conf_score += 20
            reasons.append("Target vulnerability is listed on CISA KEV catalog (+20)")

        # Adjust based on proxy/fingerprint anomalies
        if "distinct IP addresses" in correlation_summary:
            conf_score += 10
            reasons.append("Device fingerprint shared across multiple IPs (+10)")

        # Evaluate Historical Context memory
        if "Risk severely reduced" in historical_context:
            conf_score -= 40
            reasons.append("Historical analysis strongly indicates false positive (-40)")
        elif hist_count > 50:
            conf_score -= 20
            reasons.append("High historical volume of identical alerts (-20)")

        conf_score = min(100, max(0, conf_score))
        confidence_reasoning = ", ".join(reasons)

        # Step 9: Determine probable root cause (with LLM fallback)
        llm_prompt = f"""You are a Lead AI Security Investigator. Analyze the following security alert and compiled evidence:
Alert: {alert.get('title')} ({attack_type})
Severity: {alert.get('severity')}
Attacker IP: {attacker_ip}
Device Fingerprint: {device_fp}
MITRE ATT&CK Classification:
- Tactic: {mitre_map['tactic_name']} ({mitre_map['tactic_id']})
- Technique: {mitre_map['technique_name']} ({mitre_map['technique_id']})
- Description: {mitre_map['description']}

Evidence Correlation:
{correlation_summary}

Collected Vulnerabilities:
{json.dumps(collected_vulns[:10])}

Collected Asset Info:
{json.dumps(collected_assets)}

User Activity History:
{json.dumps(user_history)}

Historical Context Memory:
{historical_context if historical_context else "No significant historical context."}

Timeline of events:
{timeline_md}

Determine the probable root cause of this alert. Explain step-by-step how the attacker succeeded or attempted to breach, referencing specific evidence above. Format the output in 2-3 sentences.
Do NOT invent any facts."""

        rc_fallback = f"Automated correlation suggests probable root cause is {attack_type} attack (MITRE {mitre_map['technique_id']}: {mitre_map['technique_name']}) targeting endpoint(s) from IP {attacker_ip}. "
        if collected_vulns:
            rc_fallback += f"Targeted host has active vulnerabilities: {', '.join(v.get('cve_id','') for v in collected_vulns if v.get('cve_id'))}."
        else:
            rc_fallback += "The attack targeted user accounts directly, suggesting brute-force or credential stuffing patterns."

        probable_root_cause = _call_llm(llm_prompt, rc_fallback)

        # Retrieve security playbooks from RAG
        rag_context = ""
        if search_knowledge:
            try:
                query_str = f"remediation playbook for {attack_type}"
                results = search_knowledge(query_str, top_k=3)
                if results:
                    rag_context = "\n".join([
                        f"--- Playbook (Source: {r.metadata.get('title', 'Unknown')}) ---\n{r.page_content}"
                        for r in results
                    ])
                    print(f"[INVESTIGATION] Found {len(results)} relevant playbook chunks in Qdrant.")
            except Exception as e:
                print(f"[INVESTIGATION] Error querying RAG engine: {e}")

        # Step 10: Recommend Remediation
        remediation_prompt = f"""Based on the root cause, evidence, and retrieved security playbooks:
Root Cause: {probable_root_cause}
Asset Info: {json.dumps(collected_assets)}
Threat Intel IP: {attacker_ip}
MITRE Classification: {mitre_map['technique_name']} ({mitre_map['technique_id']})

Retrieved Security Playbook Context:
{rag_context if rag_context else "No specific playbook found. Use standard mitigation procedures."}

Provide a numbered list of 3-5 immediate and long-term recommended actions for the SOC team to remediate this incident. If playbook context is provided, ensure your recommendations align with the playbooks. Be extremely specific and actionable.
Format as markdown list. Do NOT invent facts."""

        rem_fallback = (
            "1. Block attacker IP " + (attacker_ip if attacker_ip else "IP") + " on WAF/firewalls immediately.\n"
            "2. Reset credentials for targeted users: " + (", ".join(user_ids) if user_ids else "affected users") + ".\n"
            "3. Enable multi-factor authentication (MFA) on all login endpoints.\n"
            "4. Apply patches for any vulnerability records detected on targeted servers."
        )
        if rag_context:
            rem_fallback += f"\n5. Reference security playbook guidelines:\n{rag_context}"
            
        recommended_remediation = _call_llm(remediation_prompt, rem_fallback)

        # Executive & Technical Summaries
        exec_prompt = f"""Write an Executive Summary of this security incident.
It should be suitable for a CISO/Executive audience. Highlight the business impact, the severity, the confidence level ({conf_score}/100), what asset was targeted, and the key remediation steps.
Include the MITRE ATT&CK tactic and technique name.
Use a professional, calm, yet urgent tone. Format in 1-2 short markdown paragraphs.
Incident Details:
- Title: {alert.get('title')}
- Target Criticality: { 'HIGH' if critical_asset_targeted else 'MEDIUM/LOW' }
- MITRE Mapping: {mitre_map['technique_name']} ({mitre_map['technique_id']}) under Tactic {mitre_map['tactic_name']}
- Root Cause: {probable_root_cause}"""

        exec_fallback = (
            f"### Executive Summary\n\n"
            f"An incident of type **{alert.get('title')}** mapped to MITRE **{mitre_map['technique_name']} ({mitre_map['technique_id']})** was detected originating from IP {attacker_ip} with a refined confidence score of {conf_score}/100. "
            f"The attack pattern targeted {len(user_ids)} accounts. The root cause analysis indicates: {probable_root_cause}. "
            f"Immediate automated containment responses have been initiated, and security teams are advised to review blocklists and account lock states."
        )
        executive_summary = _call_llm(exec_prompt, exec_fallback)

        tech_prompt = f"""Write a Technical Summary of this security incident for SOC analysts.
Detail the exact TTPs (Tactics, Techniques, and Procedures), evidence correlation, timeline details, vulnerability matchings, device fingerprint details, and step-by-step root cause.
Highlight the MITRE ATT&CK mapping: Tactic {mitre_map['tactic_name']} ({mitre_map['tactic_id']}), Technique {mitre_map['technique_name']} ({mitre_map['technique_id']}).

Retrieved Security Playbook Context:
{rag_context if rag_context else "No specific playbook found."}

Format in markdown with subheadings: Technical Analysis, Evidence Correlation, Playbook Alignment, and TTP Mapping. Under Playbook Alignment, explain how the attack conforms or relates to the retrieved playbook guidelines.
Incident Details:
- Title: {alert.get('title')}
- Attacker: {attacker_ip} / FP: {device_fp}
- Correlation: {correlation_summary}
- Timeline: {timeline_md}"""

        tech_fallback = (
            f"### Technical Summary\n\n"
            f"#### Technical Analysis\n"
            f"The detection engine triggered {alert.get('title')} following suspicious events from IP {attacker_ip} using device fingerprint {device_fp}.\n\n"
            f"#### Evidence Correlation\n"
            f"{correlation_summary}\n\n"
            f"#### Playbook Alignment\n"
            f"The remediation actions were aligned with: " + (f"retrieved playbook chunks:\n{rag_context}" if rag_context else "standard operating procedures.") + "\n\n"
            f"#### TTP Mapping\n"
            f"- **MITRE ATT&CK Tactic:** {mitre_map['tactic_name']} ({mitre_map['tactic_id']})\n"
            f"- **MITRE ATT&CK Technique:** {mitre_map['technique_name']} ({mitre_map['technique_id']})\n\n"
            f"#### Timeline\n"
            f"{timeline_md}"
        )
        technical_summary = _call_llm(tech_prompt, tech_fallback)

        # Insert the investigation record
        conn.execute("DELETE FROM investigations WHERE alert_id = ?", (alert_id,))
        conn.execute(
            "INSERT INTO investigations ("
            "    alert_id, incident_id, collected_logs, collected_assets, "
            "    collected_vulnerabilities, collected_user_history, collected_previous_incidents, "
            "    correlation_summary, timeline, confidence_score, probable_root_cause, "
            "    recommended_remediation, executive_summary, technical_summary"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                alert_id, incident_id, json.dumps(related_logs, default=serialize_datetime), json.dumps(collected_assets, default=serialize_datetime),
                json.dumps(collected_vulns, default=serialize_datetime), json.dumps(user_history, default=serialize_datetime), json.dumps(previous_incidents, default=serialize_datetime),
                correlation_summary, timeline_md, conf_score, probable_root_cause,
                recommended_remediation, executive_summary, technical_summary
            )
        )
        conn.commit()
        
        # Get the investigation ID
        cur_inv = conn.execute("SELECT id FROM investigations WHERE alert_id = ?", (alert_id,))
        inv_id = cur_inv.fetchone()["id"]
        
    print(f"[INVESTIGATION] Completed investigation for Alert ID: {alert_id}. ID: {inv_id}")
    return {
        "investigation_id": inv_id,
        "alert_id": alert_id,
        "incident_id": incident_id,
        "confidence_score": conf_score,
        "confidence_reasoning": confidence_reasoning,
        "probable_root_cause": probable_root_cause,
        "recommended_remediation": recommended_remediation,
        "executive_summary": executive_summary,
        "technical_summary": technical_summary
    }
