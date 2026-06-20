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

from backend.purple_team.sigma_generator import generate_sigma_rule
from backend.purple_team.orchestrator import run_purple_team_cycle

class TestPurpleTeam(unittest.TestCase):
    
    @patch('backend.purple_team.sigma_generator._call_llm')
    def test_sigma_generator_mocked(self, mock_llm):
        mock_llm.return_value = """
```yaml
title: Detect Suspicious Task
id: e1d1a1b1-2e2d-3d3c-4b4b-550e84000000
status: experimental
description: Detects threat actor technique
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'mimikatz'
    condition: selection
level: high
```
"""
        res = generate_sigma_rule("T1003", "Credential Dumping")
        self.assertEqual(res["technique_id"], "T1003")
        self.assertIn("title: Detect Suspicious Task", res["rule_yaml"])
        self.assertIn("CommandLine|contains: 'mimikatz'", res["rule_yaml"])

    @patch('backend.purple_team.orchestrator.generate_sigma_rule')
    @patch('backend.purple_team.orchestrator.get_db')
    def test_purple_team_cycle_detected(self, mock_db, mock_sigma):
        # Setup mocks
        mock_conn = MagicMock()
        mock_db.return_value.__enter__.return_value = mock_conn
        
        # Mock cursor search returning an alert (detected)
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = {"id": 42, "timestamp": "2026-06-19T07:41:00Z"}
        mock_conn.execute.return_value = mock_cursor
        
        res = run_purple_team_cycle("T1110.004", "Credential Stuffing", "192.168.1.50")
        
        self.assertTrue(res["detected"])
        self.assertEqual(res["alert_id"], 42)
        self.assertFalse(res["rule_generated"])
        self.assertFalse(mock_sigma.called)

    @patch('backend.purple_team.orchestrator.generate_sigma_rule')
    @patch('backend.purple_team.orchestrator.get_db')
    def test_purple_team_cycle_missed(self, mock_db, mock_sigma):
        # Setup mocks
        mock_conn = MagicMock()
        mock_db.return_value.__enter__.return_value = mock_conn
        
        # Mock cursor search returning NO alert (missed)
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = None
        
        # For the INSERT query inside generate_sigma_rule / staged rules
        mock_cursor.lastrowid = 123
        mock_conn.execute.return_value = mock_cursor
        
        # Mock generated rule
        mock_sigma.return_value = {"technique_id": "T1110.004", "rule_yaml": "title: Detect Stuffing"}
        
        res = run_purple_team_cycle("T1110.004", "Credential Stuffing", "192.168.1.50")
        
        self.assertFalse(res["detected"])
        self.assertTrue(res["rule_generated"])
        self.assertEqual(res["staged_rule_id"], 123)
        self.assertEqual(res["rule_content"], "title: Detect Stuffing")
        mock_sigma.assert_called_once()

if __name__ == "__main__":
    unittest.main()
