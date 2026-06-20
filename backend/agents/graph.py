from langgraph.graph import StateGraph, END
from agents.state import AgentState
from agents.nodes import (
    planner_agent,
    supervisor_agent,
    threat_hunter_agent,
    detection_engineering_agent,
    malware_analysis_agent,
    root_cause_agent,
    knowledge_agent,
    soar_agent,
    reporting_agent,
    executive_agent,
    memory_enrichment_node,
    memory_learning_node,
    # Legacy wrapper imports
    soc_analyst_agent,
    vulnerability_agent,
    incident_response_agent,
    executive_reporting_agent
)

def route_next_agent(state: AgentState) -> str:
    """Read the supervisor's decision from the state and route to that agent."""
    next_agent = state.get("next_agent", "executive")
    valid_agents = [
        "threat_hunter", "credential_hunter", "cloud_hunter", "specialized_malware_hunter",
        "detection_engineering", "malware_analysis",
        "root_cause", "knowledge", "soar", "reporting", "executive"
    ]
    if next_agent not in valid_agents:
        return "executive"
    return next_agent

def build_soc_agent_graph():
    workflow = StateGraph(AgentState)
    
    # Add nodes
    from agents.nodes import credential_hunter_node, cloud_hunter_node, specialized_malware_hunter_node
    
    workflow.add_node("memory_recall", memory_enrichment_node)
    workflow.add_node("planner", planner_agent)
    workflow.add_node("supervisor", supervisor_agent)
    workflow.add_node("threat_hunter", threat_hunter_agent)
    workflow.add_node("credential_hunter", credential_hunter_node)
    workflow.add_node("cloud_hunter", cloud_hunter_node)
    workflow.add_node("specialized_malware_hunter", specialized_malware_hunter_node)
    workflow.add_node("detection_engineering", detection_engineering_agent)
    workflow.add_node("malware_analysis", malware_analysis_agent)
    workflow.add_node("root_cause", root_cause_agent)
    workflow.add_node("knowledge", knowledge_agent)
    workflow.add_node("soar", soar_agent)
    workflow.add_node("reporting", reporting_agent)
    workflow.add_node("executive", executive_agent)
    workflow.add_node("memory_learn", memory_learning_node)
    
    # Entry and initial plan creation
    workflow.set_entry_point("memory_recall")
    workflow.add_edge("memory_recall", "planner")
    workflow.add_edge("planner", "supervisor")
    
    # Conditional routing from supervisor
    workflow.add_conditional_edges(
        "supervisor",
        route_next_agent,
        {
            "threat_hunter": "threat_hunter",
            "credential_hunter": "credential_hunter",
            "cloud_hunter": "cloud_hunter",
            "specialized_malware_hunter": "specialized_malware_hunter",
            "detection_engineering": "detection_engineering",
            "malware_analysis": "malware_analysis",
            "root_cause": "root_cause",
            "knowledge": "knowledge",
            "soar": "soar",
            "reporting": "reporting",
            "executive": "executive"
        }
    )
    
    # All analysis agents route back to supervisor to process next subtask
    workflow.add_edge("threat_hunter", "supervisor")
    workflow.add_edge("credential_hunter", "supervisor")
    workflow.add_edge("cloud_hunter", "supervisor")
    workflow.add_edge("specialized_malware_hunter", "supervisor")
    workflow.add_edge("detection_engineering", "supervisor")
    workflow.add_edge("malware_analysis", "supervisor")
    workflow.add_edge("root_cause", "supervisor")
    workflow.add_edge("knowledge", "supervisor")
    workflow.add_edge("soar", "supervisor")
    workflow.add_edge("reporting", "supervisor")
    
    # Executive compiles outcomes and commits back to memory learn
    workflow.add_edge("executive", "memory_learn")
    workflow.add_edge("memory_learn", END)
    
    return workflow.compile()

soc_orchestrator = build_soc_agent_graph()

def run_soc_investigation(task_description: str, tenant_id: str = "default"):
    """Entry point to run the full hierarchical agent society workflow."""
    initial_state = {
        "task": task_description,
        "tenant_id": tenant_id,
        "messages": [],
        "findings": {},
        "subtasks": [],
        "current_subtask_index": 0,
        "next_agent": "",
        "confidence_score": 0.0,
        "reflection_count": 0,
        "max_reflections": 3,
        "consensus_debate": []
    }
    
    # Prevent infinite loops with recursion_limit configuration
    result = soc_orchestrator.invoke(initial_state, config={"recursion_limit": 50})
    return result
