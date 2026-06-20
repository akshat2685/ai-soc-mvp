import sys
import os
import unittest
from unittest.mock import MagicMock, patch

# Add backend directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.digital_twin.engine import calculate_blast_radius, find_attack_paths, calculate_critical_asset_exposure, get_network_topology
from backend.digital_twin.simulation import simulate_attack, cleanup_simulations

class TestDigitalTwin(unittest.TestCase):
    
    def setUp(self):
        # Setup mocks or default parameters
        self.start_node = "192.168.1.50"
        
    @patch('backend.digital_twin.engine.run_cypher')
    def test_calculate_blast_radius_mocked(self, mock_run):
        # Mock Neo4j response
        mock_run.return_value = [
            {"from_label": "IP", "from_id": "192.168.1.50", "rel": "CONNECTED_TO", "to_label": "IP", "to_id": "192.168.1.100", "criticality": "High", "is_simulated": False}
        ]
        
        res = calculate_blast_radius("IP", self.start_node)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["to_id"], "192.168.1.100")
        mock_run.assert_called_once()
        
    @patch('backend.digital_twin.simulation.run_cypher')
    @patch('database.get_db')
    def test_simulate_attack_mocked(self, mock_db, mock_run):
        # Mock run_cypher responses depending on the query
        def run_cypher_side_effect(query, **kwargs):
            if "MATCH (n) WHERE" in query:
                return [{"label": "IP", "identifier": "192.168.1.50", "criticality": "Medium"}]
            elif "MATCH p=(start)" in query:
                return [{"label": "Host", "target_id": "ast-xyz123", "criticality": "High", "distance": 1}]
            elif "MATCH (a) WHERE" in query:
                return [] # MERGE relationship creation returns nothing
            elif "MATCH (n) RETURN count" in query:
                return [{"c": 10}]
            return []

        mock_run.side_effect = run_cypher_side_effect
        
        # Mock SQLite connection
        mock_conn = MagicMock()
        mock_db.return_value.__enter__.return_value = mock_conn
        
        res = simulate_attack("192.168.1.50", "RANSOMWARE", risk_factor=0.8)
        
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["attack_type"], "RANSOMWARE")
        self.assertEqual(res["affected_nodes_count"], 1)
        self.assertEqual(res["critical_assets_at_risk"], 1)
        
        # Verify SQL inserts are called
        self.assertTrue(mock_conn.execute.called)

    def test_degraded_mode_no_crash(self):
        # Calling digital twin functions when Neo4j is offline should return empty data structures instead of crashing
        res_radius = calculate_blast_radius("Host", "offline-host")
        self.assertEqual(res_radius, [])
        
        res_path = find_attack_paths("host-a", "host-b")
        self.assertEqual(res_path, [])
        
        res_exposure = calculate_critical_asset_exposure()
        self.assertEqual(res_exposure, [])

if __name__ == "__main__":
    unittest.main()
