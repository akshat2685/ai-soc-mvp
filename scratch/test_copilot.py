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

from copilot.api import init_copilot_tables, router
from fastapi.testclient import TestClient
from fastapi import FastAPI

class TestSecurityCopilot(unittest.TestCase):

    @patch('copilot.api.get_db')
    def test_table_initialization(self, mock_db):
        """Verify database tables are created correctly."""
        mock_conn = MagicMock()
        mock_db.return_value.__enter__.return_value = mock_conn

        init_copilot_tables()
        self.assertTrue(mock_conn.execute.called)

    @patch('copilot.api.get_db')
    @patch('copilot.api._call_llm')
    def test_copilot_chat_logic(self, mock_llm, mock_db):
        """Verify chat analysis outputs markdown response with citations and confidence."""
        mock_conn = MagicMock()
        mock_db.return_value.__enter__.return_value = mock_conn

        # Mock the LLM output
        mock_llm.return_value = "Based on our analysis, host-101 is suspicious because of [Source: Neo4j Host-101]."

        # Mock incident fetch in postgres
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [
            {
                "id": 1,
                "title": "Suspicious login spikes",
                "severity": "HIGH",
                "status": "ACTIVE"
            }
        ]
        mock_conn.execute.return_value = mock_cursor

        # Create test client for FastAPI router
        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)

        # Mock require_auth dependency override
        app.dependency_overrides[router.dependencies[0].dependency if router.dependencies else None] = lambda: {"username": "admin", "tenant_id": "default"}

        payload = {
            "conversation_id": "conv_test_123",
            "question": "Why is host suspicious?",
            "history": [],
            "context_drilldown": {"host_id": "host-101"}
        }

        # We manually bypass require_auth inside test by mocking get_user_from_token
        with patch('copilot.api.get_user_from_token') as mock_auth:
            mock_auth.return_value = {"username": "admin", "tenant_id": "default"}
            
            headers = {"Authorization": "Bearer mock-token-123"}
            response = client.post("/api/v1/copilot/chat", json=payload, headers=headers)
            
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertIn("host-101 is suspicious", data["answer"])
            self.assertGreaterEqual(len(data["citations"]), 1)
            self.assertGreaterEqual(len(data["reasoning_steps"]), 1)
            self.assertEqual(data["confidence_score"], 0.90)

if __name__ == "__main__":
    unittest.main()
