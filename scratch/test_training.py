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

from training.data_collector import collect_training_data
from training.lora_pipeline import run_fine_tuning
from training.api import init_training_table, router

class TestModelTraining(unittest.TestCase):

    @patch('training.data_collector.get_db')
    def test_data_collection(self, mock_db):
        """Test dataset formatting and collection from SQLite/Postgres alerts and SOAR logs."""
        mock_conn = MagicMock()
        mock_db.return_value.__enter__.return_value = mock_conn

        mock_cursor = MagicMock()
        mock_cursor.fetchall.side_effect = [
            # Alerts mock
            [
                {
                    "id": 1,
                    "title": "Credential Stuffing detected",
                    "severity": "CRITICAL",
                    "attack_type": "CREDENTIAL_STUFFING",
                    "evidence": "100 failed attempts",
                    "llm_summary": "Active brute force attempt",
                    "verdict": "TRUE_POSITIVE"
                }
            ],
            # SOAR mock
            [
                {
                    "playbook_name": "IP block",
                    "target": "192.168.1.50",
                    "status": "COMPLETED"
                }
            ]
        ]
        mock_conn.execute.return_value = mock_cursor

        dataset_path = collect_training_data("default")
        self.assertTrue(os.path.exists(dataset_path))
        
        # Check output structure
        with open(dataset_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
            self.assertEqual(len(lines), 2)

    @patch('training.lora_pipeline.get_db')
    def test_fine_tuning_runner_mock(self, mock_db):
        """Test fine-tuning pipeline simulation and adapter saving under offline fallback mode."""
        mock_conn = MagicMock()
        mock_db.return_value.__enter__.return_value = mock_conn

        dataset_path = "backend/training/data/dataset.jsonl"
        os.makedirs("backend/training/data", exist_ok=True)
        with open(dataset_path, "w") as f:
            f.write('{"instruction": "test", "input": "", "output": "test"}\n')

        res = run_fine_tuning("Qwen3", dataset_path)
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["base_model"], "Qwen3")
        self.assertEqual(res["mode"], "mock") # Fails soft to simulated mode in sandbox
        self.assertTrue(os.path.exists(f"{res['model_dir']}/adapter_config.json"))

if __name__ == "__main__":
    unittest.main()
