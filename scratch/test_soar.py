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

from soar.config import save_integration_config, get_integration_config
from soar.approvals import request_approval, resolve_approval
from soar.playbooks import trigger_playbook, trigger_rollback

class TestSOAREngine(unittest.TestCase):

    @patch('soar.config.get_db')
    def test_config_management(self, mock_db):
        """Test tenant-specific configuration saving and loading."""
        mock_conn = MagicMock()
        mock_db.return_value.__enter__.return_value = mock_conn

        # Mock database fetch (returns custom config first, then default, then nothing)
        mock_cursor = MagicMock()
        mock_cursor.fetchone.side_effect = [
            ('{"webhook_url": "https://hooks.slack.com/custom"}',), # custom tenant
            None, # default fallback
        ]
        mock_conn.execute.return_value = mock_cursor

        # Test retrieving tenant config
        config = get_integration_config("tenant-abc", "slack")
        self.assertEqual(config.get("webhook_url"), "https://hooks.slack.com/custom")

        # Test default fallback when tenant custom config doesn't exist
        mock_cursor.fetchone.side_effect = [
            None, # custom tenant is None
            ('{"webhook_url": "https://hooks.slack.com/default"}',), # default fallback
        ]
        config = get_integration_config("tenant-abc", "slack")
        self.assertEqual(config.get("webhook_url"), "https://hooks.slack.com/default")

    @patch('soar.approvals.get_db')
    @patch('soar.integrations.slack.send_message')
    @patch('soar.integrations.teams.send_message')
    def test_approvals_workflow(self, mock_teams, mock_slack, mock_db):
        """Test approval request creation and Slack/Teams notification trigger."""
        mock_conn = MagicMock()
        mock_db.return_value.__enter__.return_value = mock_conn
        
        mock_cursor = MagicMock()
        mock_cursor.lastrowid = 100
        mock_conn.cursor.return_value = mock_cursor

        app_id = request_approval("tenant-xyz", 5, "block_paloalto", "192.168.10.12")
        self.assertEqual(app_id, 100)
        
        # Verify Slack and Teams were notified
        mock_slack.assert_called_once()
        mock_teams.assert_called_once()

    @patch('soar.playbooks.get_db')
    @patch('soar.playbooks.run_action_with_retries')
    def test_playbook_trigger_and_retry(self, mock_run_action, mock_db):
        """Test playbook trigger, action creation, and run."""
        mock_conn = MagicMock()
        mock_db.return_value.__enter__.return_value = mock_conn
        
        mock_cursor = MagicMock()
        mock_cursor.lastrowid = 200
        mock_conn.cursor.return_value = mock_cursor

        # Mock the query fetching the playbook run
        mock_cursor.fetchone.side_effect = [
            {
                "id": 200,
                "tenant_id": "tenant-123",
                "playbook_name": "Ticket creation",
                "target": "user@org.com",
                "incident_id": 999
            },
            None, # action run 1 fetch
            None, # action run 2 fetch
        ]
        mock_conn.execute.return_value = mock_cursor
        mock_run_action.return_value = (True, {"status": "success"}, {"ticket_key": "SEC-12"}, "")

        # Trigger playbook
        run_id = trigger_playbook("tenant-123", "Ticket creation", "user@org.com", 999)
        self.assertEqual(run_id, 200)
        self.assertEqual(mock_run_action.call_count, 2)

    @patch('soar.playbooks.get_db')
    @patch('soar.playbooks.execute_rollback_action')
    def test_playbook_rollback(self, mock_rollback_action, mock_db):
        """Test automatic rollback execution for completed actions when playbook fails."""
        mock_conn = MagicMock()
        mock_db.return_value.__enter__.return_value = mock_conn
        
        mock_cursor = MagicMock()
        # Mock completed action runs in reverse order
        mock_cursor.fetchall.return_value = [
            {
                "id": 50,
                "playbook_run_id": 300,
                "action_name": "create_jira",
                "integration_name": "jira",
                "rollback_data": '{"ticket_key": "SEC-98"}'
            }
        ]
        mock_cursor.fetchone.return_value = ("tenant-123",)
        mock_conn.execute.return_value = mock_cursor

        mock_rollback_action.return_value = {"status": "success"}

        trigger_rollback(300)
        mock_rollback_action.assert_called_once_with("tenant-123", "jira", {"ticket_key": "SEC-98"})

if __name__ == "__main__":
    unittest.main()
