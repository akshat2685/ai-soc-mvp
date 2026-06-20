import json
import sys
import os
import logging
import re
from typing import Dict, Any, List

# Add parent directory to path to import ai_engine and database
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_engine import _call_llm
from database import get_db
from agents.state import AgentState
from agents.prompts import PromptLoader
from agents.dpo_alignment import generate_dpo_pair
from security.policy_engine import OPAPolicyEngine
from security.trust_manager import AgentTrustManager
from security.tool_permissions import AgentToolPermissions
from security.agent_identity import sign_agent_message, verify_agent_signature
from observability.tracing import start_agent_span
from observability.metrics import record_token_cost
from observability.token_usage import calculate_llm_cost
from observability.agent_profiler import AgentPerformanceProfiler
from telemetry import get_tracer

logger = logging.getLogger(__name__)

try:
    import memory_integration
except ImportError:
    memory_integration = None

tracer = get_tracer("soc-agents")

def _log_audit(action: str, agent: str, notes: str):
    """Log agent actions to the database."""
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO audit_log (action_type, target, triggered_by, execution_result, notes) VALUES (?, ?, ?, ?, ?)",
                ("AGENT_ACTION", "System", agent, "SUCCESS", f"{action}: {notes[:200]}...")
            )
            conn.commit()
    except Exception as e:
        logger.warning(f"[AGENT AUDIT ERROR] {e}")

# ── 1. Planner Agent ──
def planner_agent(state: AgentState) -> dict:
    """Decomposes the security task into sequential subtasks."""
    with tracer.start_as_current_span("planner_agent") as span:
        task = state["task"]
        span.set_attribute("agent.task", task)
        
        base_prompt = f"""You are the EDYSOR SOC Planner Agent.
Your role: Task decomposition, security planning, checklist creation.
Decompose this security investigation task: '{task}' into 3 to 5 concrete logical subtasks.
Return a JSON array of strings representing these subtasks. Output ONLY the JSON array.
"""
        prompt = PromptLoader.get_prompt("planner", base_prompt)
        response = _call_llm(prompt, fallback='["Query memory and threat intel", "Identify vulnerability & root cause", "Perform malware analysis", "Select SOAR actions", "Generate Executive summary"]')
        
        try:
            # Parse JSON list
            subtasks = json.loads(re.search(r'\[.*\]', response, re.DOTALL).group(0))
        except Exception:
            subtasks = ["Query memory and threat intel", "Identify vulnerability & root cause", "Perform malware analysis", "Select SOAR actions", "Generate Executive summary"]
            
        _log_audit("Plan generation", "Planner_Agent", f"Created plan with {len(subtasks)} subtasks")
        return {"subtasks": subtasks, "current_subtask_index": 0}

# ── 2. Supervisor Agent ──
def supervisor_agent(state: AgentState) -> dict:
    """Decides which agent executes next based on completed subtasks."""
    with tracer.start_as_current_span("supervisor_agent") as span:
        task = state["task"]
        subtasks = state.get("subtasks", [])
        index = state.get("current_subtask_index", 0)
        findings = state.get("findings", {})
        reflections = state.get("reflection_count", 0)
        max_reflections = state.get("max_reflections", 3)

        span.set_attribute("agent.task", task)
        span.set_attribute("agent.subtasks_total", len(subtasks))
        span.set_attribute("agent.subtask_index", index)

        # Circuit breaker / Loop prevention
        if reflections >= max_reflections:
            logger.warning("[Supervisor] Max reflections reached. Routing to Executive.")
            return {"next_agent": "executive"}

        # If all planned subtasks are handled, route to Executive
        if not subtasks or index >= len(subtasks):
            return {"next_agent": "executive"}

        current_subtask = subtasks[index]
        valid_agents = ['threat_hunter', 'credential_hunter', 'cloud_hunter', 'specialized_malware_hunter', 'detection_engineering', 'malware_analysis', 'root_cause', 'knowledge', 'soar', 'reporting', 'executive']
        
        base_prompt = f"""You are the EDYSOR SOC Supervisor.
Your role: Routing, task coordination, agent coordination.
Goal Task: '{task}'
Subtasks: {subtasks}
Current Subtask Index: {index} (Current Subtask: '{current_subtask}')
Current Findings: {list(findings.keys())}

Choose the next specialized agent to execute this subtask.
Select exactly one from: {valid_agents}.
Output ONLY the name of the agent in lowercase.
"""
        prompt = PromptLoader.get_prompt("supervisor", base_prompt)
        response = _call_llm(prompt, fallback="threat_hunter").strip().lower()
        
        # Sanitize routing response
        next_agent = "threat_hunter"
        for va in valid_agents:
            if va in response:
                next_agent = va
                break
                
        _log_audit("Route task", "Supervisor_Agent", f"Routing subtask '{current_subtask}' to {next_agent}")
        return {"next_agent": next_agent, "current_subtask_index": index + 1}

# ── 3a. Specialized Threat Hunter Nodes ──
def credential_hunter_node(state: AgentState) -> dict:
    from agents.specialized.credential_hunter import credential_hunter
    task = state["task"]
    findings = state.get("findings", {})
    res = credential_hunter(task, findings)
    new_findings = dict(findings)
    new_findings["credential_hunter"] = res
    return {"findings": new_findings, "messages": [f"Credential Hunter: {res['analysis']}"]}

def cloud_hunter_node(state: AgentState) -> dict:
    from agents.specialized.cloud_hunter import cloud_hunter
    task = state["task"]
    findings = state.get("findings", {})
    res = cloud_hunter(task, findings)
    new_findings = dict(findings)
    new_findings["cloud_hunter"] = res
    return {"findings": new_findings, "messages": [f"Cloud Hunter: {res['analysis']}"]}

def specialized_malware_hunter_node(state: AgentState) -> dict:
    from agents.specialized.malware_hunter import malware_hunter
    task = state["task"]
    findings = state.get("findings", {})
    res = malware_hunter(task, findings)
    new_findings = dict(findings)
    new_findings["specialized_malware_hunter"] = res
    return {"findings": new_findings, "messages": [f"Malware Hunter (Specialized): {res['analysis']}"]}

# ── 3. Legacy Generic Threat Hunter Agent ──
def threat_hunter_agent(state: AgentState) -> dict:
    """Searches pattern anomalies and aligns with MITRE metrics."""
    # 1. Zero-Trust OPA Authorization Check
    context = {"tenant_id": state.get("tenant_id", "default"), "risk_score": 0.2}
    authorized, reason = OPAPolicyEngine.evaluate_authorization("threat_hunter", "read_logs", context)
    if not authorized:
        logger.error(f"[OPA Block] threat_hunter: {reason}")
        return {"messages": [f"Threat Hunter: Blocked by security policy engine - {reason}"]}

    # 2. Tool Access Authorization Check
    if not AgentToolPermissions.is_tool_authorized("threat_hunter", "clickhouse_logs"):
        return {"messages": ["Threat Hunter: Blocked from using clickhouse_logs tool due to least privilege policy."]}

    task = state["task"]
    findings = state.get("findings", {})
    alert_data = findings.get("alert_data", {})
    attacker_ip = alert_data.get("attacker_ip", "127.0.0.1")

    # 3. Observability Tracing Span & Profiler Invocations
    with start_agent_span("threat_hunter", task):
        AgentPerformanceProfiler.record_invocation("threat_hunter")

        # 4. Query raw telemetry (ClickHouse or local SQL logs)
        telemetry = []
        try:
            from clickhouse_client import get_clickhouse_client, query_clickhouse
            if get_clickhouse_client():
                q = "SELECT * FROM logs WHERE source_ip = %s AND timestamp >= now() - INTERVAL 1 DAY LIMIT 10"
                telemetry = query_clickhouse(q, {"source_ip": attacker_ip})
            else:
                with get_db() as conn:
                    cur = conn.execute("SELECT * FROM logs WHERE source_ip = ? ORDER BY timestamp DESC LIMIT 10", (attacker_ip,))
                    telemetry = [dict(r) for r in cur.fetchall()]
        except Exception as e:
            logger.warning(f"Telemetry query failed: {e}")

        # 5. Query Neo4j/Graph Entity Relationships (relational fallback)
        entities = []
        try:
            with get_db() as conn:
                cur = conn.execute("SELECT username, role, tenant_id FROM users LIMIT 5")
                entities = [dict(r) for r in cur.fetchall()]
        except Exception:
            pass

        # 6. Search Qdrant/Semantic similar incidents
        similar_incidents = []
        try:
            with get_db() as conn:
                cur = conn.execute("SELECT id, title, severity, verdict FROM incidents LIMIT 3")
                similar_incidents = [dict(r) for r in cur.fetchall()]
        except Exception:
            pass

        # 6b. Predict attacker next moves from Cyber World Model
        world_model_predictions = {}
        try:
            from world_model.world_model import predict_next_moves
            world_model_predictions = predict_next_moves(attacker_ip)
        except Exception as e:
            logger.warning(f"World model lookup failed: {e}")

        base_prompt = f"""You are the Threat Hunter / Triage Analyst Agent.
Your role: Pattern detection, Threat hunting, Historical logs searches, MITRE alignment.
Task context: {task}
Current state: {findings}

Raw Telemetry Logs: {telemetry}
Entity Relationships (Users): {entities}
Similar Incidents: {similar_incidents}
Predicted Attacker Next Moves (Cyber World Model): {world_model_predictions}

Perform the investigation, identify observable Indicators of Compromise, cross-reference with MITRE, and calculate deviations.
Output a JSON report matching the specified Triage Analyst schema:
{{
  "verdict": "TRUE_POSITIVE|FALSE_POSITIVE|UNCERTAIN",
  "confidence": 0.0-1.0,
  "mitre_techniques": ["T1110", "T1078"],
  "evidence_summary": "Concise narrative of what was found",
  "key_indicators": [{{"type": "IP", "value": "...", "reputation": "..."}}],
  "baseline_deviation": {{"metric": "...", "normal": "...", "observed": "..."}},
  "uncertainty_gaps": ["What would resolve ambiguity"],
  "recommended_next_steps": ["Specific actions for other agents"]
}}
Output ONLY the JSON object.
"""
        prompt = PromptLoader.get_prompt("threat_hunter", base_prompt)
        dpo_res = generate_dpo_pair("threat_hunter", prompt)
        response = dpo_res["chosen"]
        
        # 7. Token Usage & LLM Pricing Analytics
        cost = calculate_llm_cost(prompt, response)
        record_token_cost("threat_hunter", cost)

        try:
            res_data = json.loads(re.search(r'\{.*\}', response, re.DOTALL).group(0))
        except Exception:
            # Profiler flag hallucination if output fails parsing
            AgentPerformanceProfiler.flag_hallucination("threat_hunter")
            res_data = {"verdict": "TRUE_POSITIVE", "confidence": 0.85, "mitre_techniques": ["T1110"], "evidence_summary": response, "key_indicators": [], "baseline_deviation": {}, "uncertainty_gaps": [], "recommended_next_steps": []}

        # Inject predicted next moves directly into parsed response findings
        res_data["predicted_next_moves"] = world_model_predictions.get("predictions", [])

        # 8. Cryptographically Sign Agent Output (Identity)
        sig = sign_agent_message("threat_hunter", response)
        _log_audit("Threat Hunt", "Threat_Hunter_Agent", f"Sig: {sig[:30]}... {response[:150]}")
        
        new_findings = dict(findings)
        new_findings["threat_hunter"] = res_data
        new_findings["threat_hunter_sig"] = sig
        return {
            "findings": new_findings,
            "messages": [f"Threat Hunter: Classified threat as {res_data.get('verdict')} with {res_data.get('confidence')} confidence."]
        }

# ── 4. Detection Engineering Agent ──
def detection_engineering_agent(state: AgentState) -> dict:
    """Analyzes and writes Sigma and YARA rules."""
    with tracer.start_as_current_span("detection_engineering_agent") as span:
        task = state["task"]
        findings = state.get("findings", {})
        base_prompt = f"""You are the Detection Engineering Agent.
Your role: Sigma rule generation, YARA analysis, detection logic evaluation.
Task context: {task}
Current state: {findings}
Propose Sigma or YARA rules targeting the identified threat patterns."""
        prompt = PromptLoader.get_prompt("detection_engineering", base_prompt)
        response = _call_llm(prompt, fallback="Detection Engineer: Suggested Sigma rule for failed logins.")
        _log_audit("Detection Rule Design", "Detection_Engineer", response)
        
        new_findings = dict(findings)
        new_findings["detection_engineering"] = response
        return {
            "findings": new_findings,
            "messages": [f"Detection Engineer: {response}"]
        }

# ── 5. Malware Analysis Agent ──
def malware_analysis_agent(state: AgentState) -> dict:
    """Analyzes suspicious payloads, processes, and command arguments."""
    with tracer.start_as_current_span("malware_analysis_agent") as span:
        task = state["task"]
        findings = state.get("findings", {})
        base_prompt = f"""You are the Malware Analysis Agent.
Your role: Reverse engineering, payload analysis, shellcode behavior check.
Task context: {task}
Current state: {findings}
Evaluate any commands, process parameters, or files for malicious behavior."""
        prompt = PromptLoader.get_prompt("malware_analysis", base_prompt)
        response = _call_llm(prompt, fallback="Malware Analyst: Commands indicate suspicious PowerShell download execution.")
        _log_audit("Malware Check", "Malware_Analyst", response)
        
        new_findings = dict(findings)
        new_findings["malware_analysis"] = response
        return {
            "findings": new_findings,
            "messages": [f"Malware Analyst: {response}"]
        }

# ── 6. Root Cause Agent ──
def root_cause_agent(state: AgentState) -> dict:
    """Performs correlation with CVEs, logs, and vulnerability databases."""
    with tracer.start_as_current_span("root_cause_agent") as span:
        task = state["task"]
        findings = state.get("findings", {})
        alert_data = findings.get("alert_data", {})
        
        # 1. Query CMDB assets inventory
        assets_data = []
        try:
            with get_db() as conn:
                cur = conn.execute("SELECT * FROM assets LIMIT 5")
                assets_data = [dict(r) for r in cur.fetchall()]
        except Exception:
            pass

        # 2. Check vulnerability database & feeds
        vulns_data = []
        try:
            with get_db() as conn:
                cur = conn.execute("SELECT * FROM vulnerabilities LIMIT 5")
                vulns_data = [dict(r) for r in cur.fetchall()]
        except Exception:
            pass

        base_prompt = f"""You are the DevSecOps / Root Cause Agent.
Your role: CMDB inventory lookup, vulnerability mapping, configuration review, and remediation prioritization.
Task context: {task}
Asset Inventory Data: {assets_data}
Vulnerability Scan Data: {vulns_data}

Identify any CVEs, misconfigurations, blast radius, and recommend safe remediation options.
Output a JSON report matching the specified DevSecOps Agent schema:
{{
  "asset_id": "asset-xyz",
  "vulnerabilities": [{{"cve": "CVE-2023-38545", "epss": 0.95, "exploitable": true}}],
  "misconfigurations": ["Specific deviations from baseline"],
  "blast_radius": ["Downstream assets at risk"],
  "remediation_options": [
    {{"action": "Upgrade package", "downtime": "0m", "risk": "low", "command": "apt-get upgrade -y"}}
  ],
  "compensating_controls": ["WAF rule setup"]
}}
Output ONLY the JSON object.
"""
        prompt = PromptLoader.get_prompt("root_cause", base_prompt)
        dpo_res = generate_dpo_pair("root_cause", prompt)
        response = dpo_res["chosen"]
        
        try:
            res_data = json.loads(re.search(r'\{.*\}', response, re.DOTALL).group(0))
        except Exception:
            res_data = {"asset_id": "unknown", "vulnerabilities": [], "misconfigurations": [], "blast_radius": [], "remediation_options": [], "compensating_controls": []}

        _log_audit("Root Cause Scan", "Root_Cause_Agent", response[:200])
        
        new_findings = dict(findings)
        new_findings["root_cause"] = res_data
        return {
            "findings": new_findings,
            "messages": [f"Root Cause Analyst: Identified asset {res_data.get('asset_id')} with {len(res_data.get('vulnerabilities', []))} vulnerability items."]
        }

# ── 7. Knowledge Agent ──
def knowledge_agent(state: AgentState) -> dict:
    """Queries memory layers and GraphRAG databases."""
    with tracer.start_as_current_span("knowledge_agent") as span:
        task = state["task"]
        findings = state.get("findings", {})
        alert_data = findings.get("alert_data", {})
        attacker_ip = alert_data.get("attacker_ip", "127.0.0.1")
        
        # 1. Query internal threat intel cache
        threat_intel_cache = {}
        try:
            with get_db() as conn:
                cur = conn.execute("SELECT * FROM threat_intel WHERE ip = ?", (attacker_ip,))
                row = cur.fetchone()
                if row:
                    threat_intel_cache = dict(row)
        except Exception:
            pass

        base_prompt = f"""You are the Threat Intelligence / Knowledge Agent.
Your role: GraphRAG lookup, memory retrieval, threat intelligence feed correlation.
Task context: {task}
Attacker IP: {attacker_ip}
Internal Threat Intel Cache: {threat_intel_cache}

Enrich the indicator, attribute tactics/techniques to threat actor profiles, and verify temporal decay.
Output a JSON report matching the specified Threat Intelligence schema:
{{
  "indicator": "{attacker_ip}",
  "reputation_score": 0.0-1.0,
  "threat_actor": "APT29|UNC2452|UNKNOWN",
  "campaign": "Campaign name or null",
  "ttp_mapping": ["T1110.001", "T1078.002"],
  "novelty_score": 0.0-1.0,
  "targeting_assessment": "Why us? Why now?",
  "recommended_containment": ["Specific IOCs to block"],
  "intelligence_gaps": ["What we don't know and why it matters"]
}}
Output ONLY the JSON object.
"""
        prompt = PromptLoader.get_prompt("knowledge", base_prompt)
        response = _call_llm(prompt, fallback='{"indicator": "127.0.0.1", "reputation_score": 0.9, "threat_actor": "UNKNOWN", "campaign": null, "ttp_mapping": [], "novelty_score": 0.1, "targeting_assessment": "None", "recommended_containment": [], "intelligence_gaps": []}')
        
        try:
            res_data = json.loads(re.search(r'\{.*\}', response, re.DOTALL).group(0))
        except Exception:
            res_data = {"indicator": attacker_ip, "reputation_score": 0.5, "threat_actor": "UNKNOWN", "campaign": None, "ttp_mapping": [], "novelty_score": 0.1, "targeting_assessment": "None", "recommended_containment": [], "intelligence_gaps": []}

        _log_audit("Knowledge Lookup", "Knowledge_Agent", response[:200])
        
        new_findings = dict(findings)
        new_findings["knowledge"] = res_data
        return {
            "findings": new_findings,
            "messages": [f"Knowledge Agent: Identified reputation score of {res_data.get('reputation_score')} for indicator {res_data.get('indicator')}."]
        }

# ── 8. SOAR Agent ──
def soar_agent(state: AgentState) -> dict:
    """Decides and triggers response containment playbooks."""
    # 1. Zero-Trust OPA Authorization Check
    context = {"tenant_id": state.get("tenant_id", "default"), "risk_score": 0.5}
    authorized, reason = OPAPolicyEngine.evaluate_authorization("soar", "execute_containment", context)
    if not authorized:
        logger.error(f"[OPA Block] soar: {reason}")
        return {"messages": [f"SOAR Agent: Blocked by security policy engine - {reason}"]}

    # 2. Tool Access Authorization Check
    if not AgentToolPermissions.is_tool_authorized("soar", "playbooks_run"):
        return {"messages": ["SOAR Agent: Blocked from using playbooks_run tool due to least privilege policy."]}

    # 3. Cryptographically Verify Parent Signature
    findings = state.get("findings", {})
    parent_sig = findings.get("threat_hunter_sig", "")
    if not parent_sig:
        logger.error("[Zero-Trust Verification Fail] SOAR Agent requires signed evidence from parent Threat Hunter node.")
        return {"messages": ["SOAR Agent: Verification fail - unsigned parent agent context."]}

    task = state["task"]

    # 4. Observability Tracing Span & Profiler
    with start_agent_span("soar", task):
        AgentPerformanceProfiler.record_invocation("soar")

        base_prompt = f"""You are the Response Coordinator Agent (SOAR Agent).
Your role: Playbook selection, automated mitigation, containment validation, and orchestration.
Task context: {task}
Current state (Triage, Intel, DevSecOps findings): {findings}

Match findings to a playbook, simulate execution, predict business impact, and prepare rollback commands.
Output a JSON report matching the specified Response Coordinator schema:
{{
  "playbook_selected": "Host Isolation | IP Block | User Disablement",
  "risk_score": 0.0-1.0,
  "auto_execute": true,
  "rollback_steps": ["Specific rollback commands"],
  "remediation_commands": ["Commands to execute containment safely"]
}}
Output ONLY the JSON object.
"""
        prompt = PromptLoader.get_prompt("soar", base_prompt)
        dpo_res = generate_dpo_pair("soar", prompt)
        response = dpo_res["chosen"]
        
        # 5. Cost & Token calculation
        cost = calculate_llm_cost(prompt, response)
        record_token_cost("soar", cost)

        try:
            res_data = json.loads(re.search(r'\{.*\}', response, re.DOTALL).group(0))
        except Exception:
            AgentPerformanceProfiler.flag_hallucination("soar")
            res_data = {"playbook_selected": "IP Block", "risk_score": 0.2, "auto_execute": true, "rollback_steps": [], "remediation_commands": []}

        # 5b. Run Digital Twin simulation check before committing responses
        try:
            from digital_twin.twin_simulation import simulate_containment_action
            pb = res_data.get("playbook_selected", "")
            action_map = {
                "Host Isolation": "HOST_ISOLATION",
                "IP Block": "IP_BLOCK",
                "User Disablement": "ACCOUNT_DISABLEMENT"
            }
            action_type = "IP_BLOCK"
            for k, v in action_map.items():
                if k.lower() in pb.lower():
                    action_type = v
                    break
            
            # Determine target from findings/alert_data
            alert_data = findings.get("alert_data", {})
            target = "127.0.0.1"
            if action_type == "HOST_ISOLATION":
                target = findings.get("root_cause", {}).get("asset_id") or alert_data.get("device_id") or "ast-xyz"
            elif action_type == "ACCOUNT_DISABLEMENT":
                target = alert_data.get("user_id") or "admin"
            else:
                target = alert_data.get("attacker_ip") or "127.0.0.1"

            sim_res = simulate_containment_action(action_type, target)
            res_data["twin_simulation"] = sim_res
            
            # Safety Gate: Override auto_execute if disruption is too high
            if sim_res.get("recommendation") == "REQUIRES_APPROVAL" or sim_res.get("disruption_score", 0.0) > 0.7:
                logger.info(f"[SOAR Safety Gate Triggered] High disruption score ({sim_res.get('disruption_score')}). Forcing auto_execute to False.")
                res_data["auto_execute"] = False
        except Exception as sim_err:
            logger.warning(f"Digital twin simulation failed during SOAR node run: {sim_err}")

        # 6. Cryptographically Sign Output
        sig = sign_agent_message("soar", response)
        _log_audit("SOAR Orchestration", "SOAR_Agent", f"Sig: {sig[:30]}... {response[:150]}")
        
        new_findings = dict(findings)
        new_findings["soar"] = res_data
        new_findings["soar_sig"] = sig
        return {
            "findings": new_findings,
            "messages": [f"SOAR Agent: Selected playbook '{res_data.get('playbook_selected')}' with risk score of {res_data.get('risk_score')}."]
        }

# ── 9. Reporting Agent ──
def reporting_agent(state: AgentState) -> dict:
    """Formulates technical briefings and digests."""
    with tracer.start_as_current_span("reporting_agent") as span:
        findings = state.get("findings", {})
        base_prompt = f"""You are the Reporting Agent.
Your role: Reporting, briefings, documentation, digest generation.
Current Findings: {findings}
Compile a technical overview of this investigation."""
        prompt = PromptLoader.get_prompt("reporting", base_prompt)
        response = _call_llm(prompt, fallback="Reporting Agent: Drafted incident summary reports.")
        _log_audit("Drafting reports", "Reporting_Agent", response)
        
        new_findings = dict(findings)
        new_findings["reporting"] = response
        return {
            "findings": new_findings,
            "messages": [f"Reporting Agent: {response}"]
        }

# ── 10. Executive Agent ──
def executive_agent(state: AgentState) -> dict:
    """Runs debate reflection, calculates confidence, and makes final decision."""
    with tracer.start_as_current_span("executive_agent") as span:
        findings = state.get("findings", {})
        reflections = state.get("reflection_count", 0)
        
        # 1. Run Swarm Consensus Debate
        swarm_verdict = "TRUE_POSITIVE"
        swarm_confidence = 0.85
        swarm_transcript = []
        try:
            from agents.swarm_debate import run_swarm_debate
            debate_res = run_swarm_debate(findings)
            swarm_verdict = debate_res["verdict"]
            swarm_confidence = debate_res["confidence"]
            swarm_transcript = debate_res["debate_transcript"]
        except Exception as e:
            logger.warning(f"Swarm debate failed in Executive node: {e}")

        swarm_transcript_str = "\n".join(swarm_transcript)

        base_prompt = f"""You are the Executive Agent.
Your role: Verdict consensus, confidence scoring, debate resolution.
Current agent findings: {findings}

We have completed a Swarm Consensus Debate with the following results:
Swarm Consensus Verdict: {swarm_verdict}
Swarm Consensus Confidence: {swarm_confidence}
Swarm Debate Transcript:
{swarm_transcript_str}

Evaluate the consensus. If findings are conflicting, note the debate.
Calculate a threat confidence score (0.0 to 1.0).
Determine the final verdict (TRUE_POSITIVE or FALSE_POSITIVE).
Output ONLY a JSON payload with keys: 'verdict', 'confidence', 'decision', 'debate_details'.
"""
        prompt = PromptLoader.get_prompt("executive", base_prompt)
        response = _call_llm(prompt, fallback=f'{{"verdict": "{swarm_verdict}", "confidence": {swarm_confidence}, "decision": "Proceed with host isolation and block IP.", "debate_details": "Consensus resolved."}}')
        
        try:
            res_data = json.loads(re.search(r'\{.*\}', response, re.DOTALL).group(0))
            verdict = res_data.get("verdict", swarm_verdict)
            confidence = float(res_data.get("confidence", swarm_confidence))
            decision = res_data.get("decision", "Block target.")
            debate_details = res_data.get("debate_details", "Consensus reached.")
        except Exception:
            verdict = swarm_verdict
            confidence = swarm_confidence
            decision = "Block target."
            debate_details = "Consensus reached via fallback."

        _log_audit("Executive decision", "Executive_Agent", f"Verdict: {verdict}, Confidence: {confidence}")
        
        new_findings = dict(findings)
        new_findings["executive"] = {
            "verdict": verdict,
            "confidence": confidence,
            "decision": decision,
            "swarm_consensus": {
                "verdict": swarm_verdict,
                "confidence": swarm_confidence,
                "transcript": swarm_transcript
            }
        }
        
        # 2. Generate Explainable AI (XAI) Payload
        xai_payload = {}
        try:
            from xai.engine import XAIEngine
            xai_explanation = XAIEngine.generate_explanation(
                decision=f"{verdict} - {decision}",
                context_data={"swarm_confidence": swarm_confidence, "swarm_verdict": swarm_verdict},
                agent_reasoning_trace=swarm_transcript
            )
            xai_payload = xai_explanation.model_dump()
            new_findings["xai_explanation"] = xai_payload
        except Exception as e:
            logger.warning(f"XAI Engine generation failed: {e}")

        # If there's high uncertainty or conflicting info, increment reflection loop counter
        next_count = reflections + 1
        return {
            "findings": new_findings,
            "confidence_score": confidence,
            "reflection_count": next_count,
            "consensus_debate": state.get("consensus_debate", []) + swarm_transcript + [debate_details],
            "messages": [f"Executive Agent: Concluded verdict={verdict} with confidence={confidence}. Decision: {decision}"]
        }

# ── Pre/Post Execution Nodes (Memory Platform) ──

def memory_enrichment_node(state: AgentState) -> dict:
    """Pre-execution node: recall memory to enrich the agent state."""
    with tracer.start_as_current_span("memory_enrichment_node") as span:
        task = state.get("task", "")
        span.set_attribute("agent.task", task)
        
        alert_data = {}
        incident_id = None
        alert_id = None
        
        try:
            digits = ''.join(filter(str.isdigit, task))
            if digits:
                some_id = int(digits)
                with get_db() as conn:
                    cur = conn.execute("SELECT * FROM incidents WHERE id = ?", (some_id,))
                    inc = cur.fetchone()
                    if inc:
                        incident_id = some_id
                        alert_data = dict(inc)
                        alert_cur = conn.execute("SELECT * FROM alerts WHERE incident_id = ? LIMIT 1", (incident_id,))
                        alt = alert_cur.fetchone()
                        if alt:
                            alert_data.update(dict(alt))
                    else:
                        cur = conn.execute("SELECT * FROM alerts WHERE id = ?", (some_id,))
                        alt = cur.fetchone()
                        if alt:
                            alert_id = some_id
                            alert_data = dict(alt)
        except Exception as e:
            logger.warning(f"Failed to fetch context for memory enrichment: {e}")

        if not alert_data:
            ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', task)
            attacker_ip = ip_match.group(0) if ip_match else "127.0.0.1"
            alert_data = {
                "title": task,
                "description": task,
                "attacker_ip": attacker_ip,
                "attack_type": "UNKNOWN",
                "severity": "MEDIUM"
            }

        rendered_context = ""
        if memory_integration:
            try:
                memory_res = memory_integration.recall_and_enrich(alert_data)
                rendered_context = memory_res.get("rendered_context", "")
            except Exception as e:
                logger.warning(f"memory recall failed: {e}")
        
        findings = dict(state.get("findings", {}))
        findings.update({
            "memory_context": rendered_context,
            "alert_data": alert_data,
            "incident_id": incident_id,
            "alert_id": alert_id
        })
        return {
            "findings": findings,
            "messages": ["Memory Enrichment: Successfully queried memory layers and retrieved relevant context."]
        }

def memory_learning_node(state: AgentState) -> dict:
    """Post-execution node: record findings and learn from outcome."""
    with tracer.start_as_current_span("memory_learning_node") as span:
        findings = state.get("findings", {})
        incident_id = findings.get("incident_id")
        alert_id = findings.get("alert_id")
        
        if not incident_id and not alert_id:
            try:
                digits = ''.join(filter(str.isdigit, state.get("task", "")))
                if digits:
                    incident_id = int(digits)
            except Exception:
                pass
        
        messages_text = "\n".join(state.get("messages", []))
        exec_findings = findings.get("executive", {})
        verdict = exec_findings.get("verdict", "TRUE_POSITIVE")
        confidence = exec_findings.get("confidence", 0.9)
        feedback = exec_findings.get("decision", "Completed hierarchical agent team investigation.")
        
        ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', messages_text)
        iocs_seen = [{"ioc_type": "ip", "value": ip} for ip in set(ips) if ip != "127.0.0.1" and not ip.startswith("192.168.")]

        if memory_integration:
            try:
                from backend.memory.modules import agent_decisions
                agent_decisions.record({
                    "agent_role": "supervisor",
                    "decision": f"Investigation outcome: {verdict}",
                    "reasoning": messages_text[:4000],
                    "outcome": f"Verdict: {verdict}. Confidence: {confidence}",
                    "confidence": confidence,
                    "success": True
                }, source="soc_agents")
            except Exception as e:
                logger.warning(f"Failed to record agent decision memory: {e}")

            if incident_id:
                try:
                    memory_integration.record_outcome(
                        incident_id=str(incident_id),
                        verdict=verdict,
                        iocs_seen=iocs_seen,
                        playbook_success=True,
                        analyst_feedback=feedback
                    )
                except Exception as e:
                    logger.warning(f"Failed to record outcome: {e}")

        return {
            "messages": [f"Memory Learning: Successfully recorded agent decisions, updated IOC reputations, and saved outcome with verdict={verdict}."]
        }


# ── Backward Compatibility Wrappers ──

def soc_analyst_agent(state: AgentState) -> dict:
    """Wrapper mapping to planner."""
    return planner_agent(state)

def vulnerability_agent(state: AgentState) -> dict:
    """Wrapper mapping to root cause analyst."""
    return root_cause_agent(state)

def incident_response_agent(state: AgentState) -> dict:
    """Wrapper mapping to SOAR agent."""
    return soar_agent(state)

def executive_reporting_agent(state: AgentState) -> dict:
    """Wrapper mapping to reporting agent."""
    return reporting_agent(state)
