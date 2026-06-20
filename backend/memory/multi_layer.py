import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class MultiLayerMemory:
    """
    Implements the 5-layer Cyber Memory System (OBJ 2).
    """
    
    def __init__(self):
        self.working_memory = {}    # Active investigations
        self.episodic_memory = []   # Historical incidents
        self.semantic_memory = {}   # Threat knowledge (embeddings)
        self.procedural_memory = {} # Playbooks
        self.reputation_memory = {} # Agent/Analyst trust scores

    def commit_working_to_episodic(self, incident_id: str):
        if incident_id in self.working_memory:
            incident = self.working_memory.pop(incident_id)
            self.episodic_memory.append(incident)
            logger.info(f"[MEMORY] Incident {incident_id} moved from Working to Episodic memory.")
            
    def update_reputation(self, agent_id: str, feedback_score: float):
        current_score = self.reputation_memory.get(agent_id, 1.0)
        # Simple exponential moving average for reputation
        new_score = (current_score * 0.8) + (feedback_score * 0.2)
        self.reputation_memory[agent_id] = round(new_score, 3)
        logger.info(f"[MEMORY] Agent {agent_id} reputation updated to {new_score:.3f}")
        
    def retrieve_semantic_context(self, query: str) -> List[Dict[str, Any]]:
        # Simulates vector search against semantic memory
        logger.info(f"[MEMORY] Retrieving semantic context for: {query}")
        return [{"source": "CVE-2026-9999", "context": "Similar attack pattern seen in historical data."}]
