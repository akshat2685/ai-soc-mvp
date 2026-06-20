import sys
import os
import unittest
from unittest.mock import patch, MagicMock

# Add backend directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from backend.agents.nodes import soar_agent
from backend.agents.state import AgentState
from database import get_db

class TestSoarSimulationIntegration(unittest.TestCase):
    def setUp(self):
        with get_db() as conn:
            # Seed test assets using actual schema
            conn.execute("DELETE FROM assets WHERE hostname IN ('soar-host-low', 'soar-host-crit')")
            conn.execute(
                "INSERT INTO assets (ip_address, hostname, os, criticality, owner) "
                "VALUES ('10.0.2.100', 'soar-host-low', 'Ubuntu 22.04', 'Low', 'John')"
            )
            conn.execute(
                "INSERT INTO assets (ip_address, hostname, os, criticality, owner) "
                "VALUES ('10.0.2.5', 'soar-host-crit', 'Windows DC', 'Critical', 'Admin')"
            )
            conn.commit()

    def tearDown(self):
        with get_db() as conn:
            conn.execute("DELETE FROM assets WHERE hostname IN ('soar-host-low', 'soar-host-crit')")
            conn.commit()

    @patch('backend.agents.nodes.generate_dpo_pair')
    @patch('backend.agents.nodes.sign_agent_message')
    @patch('backend.agents.nodes.verify_agent_signature')
    @patch('backend.agents.nodes.OPAPolicyEngine.evaluate_authorization')
    @patch('backend.agents.nodes.AgentToolPermissions.is_tool_authorized')
    def test_soar_gate_low_disruption_passes(self, mock_tool, mock_opa, mock_verify, mock_sign, mock_dpo):
        mock_opa.return_value = (True, "Authorized")
        mock_tool.return_value = True
        mock_verify.return_value = True
        mock_sign.return_value = "mocked_signature"
        
        mock_dpo.return_value = {
            "chosen": '{"playbook_selected": "Host Isolation", "risk_score": 0.2, "auto_execute": true, "rollback_steps": [], "remediation_commands": []}',
            "rejected": '{"playbook_selected": "Host Isolation", "risk_score": 0.2, "auto_execute": true, "rollback_steps": [], "remediation_commands": []}'
        }

        state: AgentState = {
            "task": "Isolate low criticality host soar-host-low",
            "tenant_id": "default",
            "messages": [],
            "findings": {
                "threat_hunter_sig": "parent_sig",
                "alert_data": {
                    "device_id": "soar-host-low"
                },
                "root_cause": {
                    "asset_id": "soar-host-low"
                }
            },
            "subtasks": [],
            "current_subtask_index": 0,
            "next_agent": "",
            "confidence_score": 0.9,
            "reflection_count": 0,
            "max_reflections": 3,
            "consensus_debate": []
        }

        res = soar_agent(state)
        self.assertIn("findings", res)
        soar_findings = res["findings"]["soar"]
        self.assertTrue(soar_findings["auto_execute"])
        self.assertEqual(soar_findings["twin_simulation"]["recommendation"], "APPROVE_AUTO_EXECUTE")

    @patch('backend.agents.nodes.generate_dpo_pair')
    @patch('backend.agents.nodes.sign_agent_message')
    @patch('backend.agents.nodes.verify_agent_signature')
    @patch('backend.agents.nodes.OPAPolicyEngine.evaluate_authorization')
    @patch('backend.agents.nodes.AgentToolPermissions.is_tool_authorized')
    def test_soar_gate_high_disruption_override(self, mock_tool, mock_opa, mock_verify, mock_sign, mock_dpo):
        mock_opa.return_value = (True, "Authorized")
        mock_tool.return_value = True
        mock_verify.return_value = True
        mock_sign.return_value = "mocked_signature"
        
        mock_dpo.return_value = {
            "chosen": '{"playbook_selected": "Host Isolation", "risk_score": 0.8, "auto_execute": true, "rollback_steps": [], "remediation_commands": []}',
            "rejected": '{"playbook_selected": "Host Isolation", "risk_score": 0.8, "auto_execute": true, "rollback_steps": [], "remediation_commands": []}'
        }

        state: AgentState = {
            "task": "Isolate Domain Controller soar-host-crit",
            "tenant_id": "default",
            "messages": [],
            "findings": {
                "threat_hunter_sig": "parent_sig",
                "alert_data": {
                    "device_id": "soar-host-crit"
                },
                "root_cause": {
                    "asset_id": "soar-host-crit"
                }
            },
            "subtasks": [],
            "current_subtask_index": 0,
            "next_agent": "",
            "confidence_score": 0.9,
            "reflection_count": 0,
            "max_reflections": 3,
            "consensus_debate": []
        }

        res = soar_agent(state)
        self.assertIn("findings", res)
        soar_findings = res["findings"]["soar"]
        self.assertFalse(soar_findings["auto_execute"])
        self.assertEqual(soar_findings["twin_simulation"]["recommendation"], "REQUIRES_APPROVAL")

if __name__ == "__main__":
    unittest.main()
