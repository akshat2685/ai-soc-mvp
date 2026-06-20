import sys
from unittest.mock import MagicMock

# Mock clickhouse_connect to prevent import error
sys.modules['clickhouse_connect'] = MagicMock()

import os
import unittest
from unittest.mock import patch

# Add backend directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agents.graph import build_soc_agent_graph, run_soc_investigation
from agents.nodes import planner_agent, supervisor_agent, executive_agent

class TestAgentSociety(unittest.TestCase):

    def test_graph_compilation(self):
        """Verify that the hierarchical StateGraph compiles without errors."""
        graph = build_soc_agent_graph()
        self.assertIsNotNone(graph)

    @patch('agents.nodes._call_llm')
    def test_planner_decomposition(self, mock_llm):
        """Verify planner agent parses task into a checklist array."""
        mock_llm.return_value = '["Subtask 1", "Subtask 2", "Subtask 3"]'
        
        state = {"task": "Investigate Ransomware on host-101", "messages": [], "findings": {}}
        res = planner_agent(state)
        
        self.assertEqual(res["subtasks"], ["Subtask 1", "Subtask 2", "Subtask 3"])
        self.assertEqual(res["current_subtask_index"], 0)

    @patch('agents.nodes._call_llm')
    def test_supervisor_routing(self, mock_llm):
        """Verify supervisor selects next agent based on task progress."""
        mock_llm.return_value = 'threat_hunter'
        
        state = {
            "task": "Investigate Ransomware on host-101",
            "subtasks": ["Hunt anomalies", "Create reports"],
            "current_subtask_index": 0,
            "findings": {},
            "reflection_count": 0,
            "max_reflections": 3
        }
        res = supervisor_agent(state)
        
        self.assertEqual(res["next_agent"], "threat_hunter")
        self.assertEqual(res["current_subtask_index"], 1)

    @patch('agents.nodes._call_llm')
    def test_executive_consensus_and_scoring(self, mock_llm):
        """Verify executive consensus assessment and confidence scoring."""
        mock_llm.return_value = '{"verdict": "TRUE_POSITIVE", "confidence": 0.95, "decision": "Isolate host", "debate_details": "Consensus reached."}'
        
        state = {
            "task": "Investigate alert",
            "findings": {"threat_hunter": "Malicious activity on port 443"},
            "reflection_count": 0,
            "consensus_debate": []
        }
        res = executive_agent(state)
        
        exec_findings = res["findings"]["executive"]
        self.assertEqual(exec_findings["verdict"], "TRUE_POSITIVE")
        self.assertEqual(exec_findings["confidence"], 0.95)
        self.assertEqual(res["confidence_score"], 0.95)
        self.assertEqual(res["reflection_count"], 1)
        self.assertIn("Consensus reached.", res["consensus_debate"])

    @patch('agents.nodes._call_llm')
    def test_supervisor_loop_prevention(self, mock_llm):
        """Verify supervisor routes to executive when reflection threshold is hit."""
        # Even if LLM wants to route to threat_hunter, the circuit breaker should override
        mock_llm.return_value = 'threat_hunter'
        
        state = {
            "task": "Investigate alert",
            "subtasks": ["Hunt anomalies", "Isolate"],
            "current_subtask_index": 0,
            "findings": {},
            "reflection_count": 3, # Threshold hit
            "max_reflections": 3
        }
        res = supervisor_agent(state)
        self.assertEqual(res["next_agent"], "executive")

if __name__ == "__main__":
    unittest.main()
