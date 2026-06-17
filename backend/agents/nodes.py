import json
import sys
import os

# Add parent directory to path to import ai_engine and database
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_engine import _call_llm
from database import get_db
from agents.state import AgentState
from telemetry import get_tracer

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
        print(f"[AGENT AUDIT ERROR] {e}")


def soc_analyst_agent(state: AgentState) -> dict:
    with tracer.start_as_current_span("soc_analyst_agent") as span:
        task = state["task"]
        span.set_attribute("agent.task", task)
        
        # Try to extract incident data if ID is passed
        context = ""
        try:
            incident_id = int(''.join(filter(str.isdigit, task)))
            with get_db() as conn:
                cur = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
                inc = cur.fetchone()
                if inc:
                    context = f"\nIncident Context: {dict(inc)}"
                    span.set_attribute("agent.incident_id", incident_id)
        except Exception:
            pass

        prompt = f"""You are the SOC Analyst Agent.
Your role: Alert triage, Investigation, Incident creation.
Task: {task}{context}
Analyze the initial alert/task and create an investigation plan."""
        
        response = _call_llm(prompt, fallback="SOC Analyst: Initiated investigation.")
        _log_audit("Triage task", "SOC_Analyst_Agent", response)
        
        span.set_attribute("agent.response", response[:1000])
        return {"messages": [f"SOC Analyst: {response}"]}


def threat_hunter_agent(state: AgentState) -> dict:
    with tracer.start_as_current_span("threat_hunter_agent") as span:
        task = state["task"]
        span.set_attribute("agent.task", task)
        
        previous_context = "\n".join(state.get("messages", [])[-2:])
        prompt = f"""You are the Threat Hunter Agent.
Your role: Pattern detection, Threat hunting, Historical searches.
Task: {task}
Context: {previous_context}
Look for related historical patterns or anomalies."""
        
        response = _call_llm(prompt, fallback="Threat Hunter: Reviewed historical patterns.")
        _log_audit("Threat Hunt", "Threat_Hunter_Agent", response)
        
        span.set_attribute("agent.response", response[:1000])
        return {"messages": [f"Threat Hunter: {response}"]}


def vulnerability_agent(state: AgentState) -> dict:
    with tracer.start_as_current_span("vulnerability_agent") as span:
        task = state["task"]
        span.set_attribute("agent.task", task)
        
        prompt = f"""You are the Vulnerability Agent.
Your role: CVE analysis, Patch prioritization, Risk scoring.
Task: {task}
Assess any related vulnerabilities or exposed assets."""
        
        response = _call_llm(prompt, fallback="Vulnerability Agent: No immediate CVEs mapped.")
        _log_audit("Vuln Scan", "Vulnerability_Agent", response)
        
        span.set_attribute("agent.response", response[:1000])
        return {"messages": [f"Vulnerability Agent: {response}"]}


def incident_response_agent(state: AgentState) -> dict:
    with tracer.start_as_current_span("incident_response_agent") as span:
        context = "\n".join(state.get("messages", []))
        
        prompt = f"""You are the Incident Response Agent.
Your role: Response recommendations, Containment plans, Recovery guidance.
Based on the investigation so far:
{context}
Provide a concrete containment strategy."""
        
        response = _call_llm(prompt, fallback="IR Agent: Containment recommended.")
        _log_audit("Containment Plan", "Incident_Response_Agent", response)
        
        span.set_attribute("agent.response", response[:1000])
        return {"messages": [f"Incident Response Agent: {response}"]}


def executive_reporting_agent(state: AgentState) -> dict:
    with tracer.start_as_current_span("executive_reporting_agent") as span:
        context = "\n".join(state.get("messages", []))
        
        prompt = f"""You are the Executive Reporting Agent.
Your role: Business summaries, Board-level reports, KPI generation.
Take the following technical findings and generate an Executive Summary for the C-Suite:
{context}"""
        
        response = _call_llm(prompt, fallback="Executive Report: Investigation handled successfully.")
        _log_audit("Report Generation", "Executive_Reporting_Agent", response)
        
        span.set_attribute("agent.response", response[:1000])
        return {"messages": [f"Executive Reporting Agent: {response}"]}
