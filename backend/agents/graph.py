from langgraph.graph import StateGraph, END
from agents.state import AgentState
from agents.nodes import (
    soc_analyst_agent,
    threat_hunter_agent,
    vulnerability_agent,
    incident_response_agent,
    executive_reporting_agent
)

def build_soc_agent_graph():
    workflow = StateGraph(AgentState)
    
    # Add nodes
    workflow.add_node("soc_analyst", soc_analyst_agent)
    workflow.add_node("threat_hunter", threat_hunter_agent)
    workflow.add_node("vulnerability", vulnerability_agent)
    workflow.add_node("incident_response", incident_response_agent)
    workflow.add_node("executive_reporting", executive_reporting_agent)
    
    # Orchestration flow: Linear Multi-Agent Investigation
    workflow.set_entry_point("soc_analyst")
    workflow.add_edge("soc_analyst", "threat_hunter")
    workflow.add_edge("threat_hunter", "vulnerability")
    workflow.add_edge("vulnerability", "incident_response")
    workflow.add_edge("incident_response", "executive_reporting")
    workflow.add_edge("executive_reporting", END)
    
    return workflow.compile()

soc_orchestrator = build_soc_agent_graph()

def run_soc_investigation(task_description: str):
    """Entry point to run the full multi-agent workflow."""
    initial_state = {
        "task": task_description,
        "messages": [],
        "findings": {},
        "next_step": ""
    }
    
    result = soc_orchestrator.invoke(initial_state)
    return result
