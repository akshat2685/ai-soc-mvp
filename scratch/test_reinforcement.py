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

from safety.guardrails import check_action_safety, get_action_explainability_trace
from learning.reinforcement import run_reinforcement_optimization_loop, generate_yara_rule

class TestSelfImprovingSOC(unittest.TestCase):

    @patch('safety.guardrails.get_db')
    def test_safety_guardrails_blocked(self, mock_db):
        """Verify safety guardrails block unsafe/critical system actions."""
        mock_conn = MagicMock()
        mock_db.return_value.__enter__.return_value = mock_conn

        # Test sensitive IP block
        is_safe, reason = check_action_safety("BLOCK_IP", "127.0.0.1")
        self.assertFalse(is_safe)
        self.assertIn("restricted internal", reason)

        # Test sensitive host isolation block
        is_safe, reason = check_action_safety("ISOLATE_HOST", "corp-dc-01")
        self.assertFalse(is_safe)
        self.assertIn("critical infrastructure", reason)

        # Test standard IP block (should be allowed)
        is_safe, reason = check_action_safety("BLOCK_IP", "185.220.101.5")
        self.assertTrue(is_safe)

    @patch('safety.guardrails.get_db')
    def test_explainability_trace(self, mock_db):
        """Verify audit trace constructs explainable decision records."""
        mock_conn = MagicMock()
        mock_db.return_value.__enter__.return_value = mock_conn
        
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = {
            "id": 88,
            "timestamp": "2026-06-19T09:30:00Z",
            "action_type": "ISOLATE_HOST",
            "target": "corp-dc-01",
            "triggered_by": "GUARDRAIL",
            "execution_result": "FAILED",
            "notes": "Guardrail Interception: hostname is critical infrastructure"
        }
        mock_conn.execute.return_value = mock_cursor

        trace = get_action_explainability_trace(88)
        self.assertEqual(trace["action_id"], 88)
        self.assertEqual(trace["result"], "FAILED")
        self.assertIn("hostname is critical infrastructure", trace["explanation"])
        self.assertTrue(len(trace["decision_flow"]) > 0)

    @patch('learning.reinforcement.get_db')
    @patch('learning.reinforcement._call_llm')
    def test_yara_rule_generation(self, mock_llm, mock_db):
        """Verify automated YARA rule syntax generation."""
        mock_conn = MagicMock()
        mock_db.return_value.__enter__.return_value = mock_conn
        mock_llm.return_value = 'rule Detect_T1003 { strings: $s = "mimikatz" condition: $s }'

        res = generate_yara_rule("T1003")
        self.assertEqual(res["rule_name"], "Detect_T1003")
        self.assertIn("mimikatz", res["yara_rule"])

    @patch('learning.reinforcement.get_db')
    @patch('learning.reinforcement.generate_sigma_rule')
    @patch('learning.reinforcement.generate_yara_rule')
    def test_closed_loop_optimization(self, mock_yara, mock_sigma, mock_db):
        """Verify playbook failure rate analysis and replacement recommendation generation."""
        mock_conn = MagicMock()
        mock_db.return_value.__enter__.return_value = mock_conn
        
        mock_cursor = MagicMock()
        # Mock action stats showing flaky jira connector (4 failures out of 5 runs)
        mock_cursor.fetchall.side_effect = [
            [
                {
                    "action_name": "create_jira",
                    "integration_name": "jira",
                    "total": 5,
                    "failures": 4
                }
            ],
            [] # missed simulations techniques list
        ]
        mock_conn.execute.return_value = mock_cursor

        res = run_reinforcement_optimization_loop("default")
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["playbook_optimizations_found"], 1)
        self.assertEqual(res["optimizations"][0]["action"], "create_jira")
        self.assertGreater(res["optimizations"][0]["failure_rate"], 0.5)

if __name__ == "__main__":
    unittest.main()
