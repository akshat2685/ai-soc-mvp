import sys
import os
import unittest
from unittest.mock import patch, MagicMock

# Add backend directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from backend.agents.nodes import executive_agent
from backend.agents.state import AgentState

class TestExecutiveDebateIntegration(unittest.TestCase):
    @patch('backend.agents.nodes._call_llm')
    def test_executive_debate_tp_consensus(self, mock_llm):
        # Mock LLM decision output
        mock_llm.return_value = '{"verdict": "TRUE_POSITIVE", "confidence": 0.85, "decision": "Proceed with host isolation.", "debate_details": "Consensus resolved."}'
        
        state: AgentState = {
            "task": "Perform final triage on compromised workstation",
            "tenant_id": "default",
            "messages": [],
            "findings": {
                "threat_hunter": {
                    "verdict": "TRUE_POSITIVE",
                    "confidence": 0.90
                },
                "root_cause": {
                    "vulnerabilities": [{"cve": "CVE-2023-38545"}]
                },
                "malware_analysis": "Powershell credential dumping detected."
            },
            "subtasks": [],
            "current_subtask_index": 0,
            "next_agent": "",
            "confidence_score": 0.0,
            "reflection_count": 0,
            "max_reflections": 3,
            "consensus_debate": []
        }

        res = executive_agent(state)
        self.assertIn("findings", res)
        self.assertIn("executive", res["findings"])
        exec_findings = res["findings"]["executive"]
        
        self.assertEqual(exec_findings["verdict"], "TRUE_POSITIVE")
        self.assertEqual(exec_findings["swarm_consensus"]["verdict"], "TRUE_POSITIVE")
        self.assertGreaterEqual(len(exec_findings["swarm_consensus"]["transcript"]), 4)
        
        # Verify transcript added to state variables
        self.assertGreater(len(res["consensus_debate"]), 4)
        self.assertTrue(any("[Threat Hunter] Argument:" in line for line in res["consensus_debate"]))

if __name__ == "__main__":
    unittest.main()
