import sys
import os
import unittest
import json
from unittest.mock import patch

# Add backend directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from backend.world_model.world_model import predict_next_moves, get_similar_vulnerabilities
from backend.attack_graph import forecast_next_stages, calculate_path_probabilities
from database import get_db

class TestWorldModelAndAttackGraph(unittest.TestCase):
    def setUp(self):
        with get_db() as conn:
            # Seed mock assets for world model traversal using correct column names
            conn.execute("DELETE FROM assets WHERE hostname LIKE 'wm-host-%'")
            conn.execute(
                "INSERT INTO assets (ip_address, hostname, os, criticality, owner) "
                "VALUES ('10.0.1.10', 'wm-host-1', 'Ubuntu 20.04', 'Medium', 'User A')"
            )
            conn.execute(
                "INSERT INTO assets (ip_address, hostname, os, criticality, owner) "
                "VALUES ('10.0.1.20', 'wm-host-2', 'Windows 10', 'High', 'User B')"
            )
            
            # Seed mock CVEs
            conn.execute("DELETE FROM cve_feed WHERE cve_id = 'CVE-TEST-9999'")
            conn.execute(
                "INSERT INTO cve_feed (cve_id, description, cvss_score, severity, published_date, last_modified_date) "
                "VALUES ('CVE-TEST-9999', 'Test memory buffer overflow in libtest service', 9.8, 'CRITICAL', '2026-01-01', '2026-01-02')"
            )
            
            # Seed mock incident, alert, investigation for Attack Graph tests
            conn.execute("DELETE FROM incidents WHERE id = 999")
            conn.execute("DELETE FROM alerts WHERE incident_id = 999")
            conn.execute("DELETE FROM investigations WHERE alert_id = 8888")
            
            conn.execute(
                "INSERT INTO incidents (id, title, severity, verdict, tenant_id) "
                "VALUES (999, 'Test Propagation Incident', 'HIGH', 'TRUE_POSITIVE', 'default')"
            )
            conn.execute(
                "INSERT INTO alerts (id, incident_id, timestamp, title, severity, attack_type, attacker_ip) "
                "VALUES (8888, 999, '2026-06-19T10:00:00Z', 'Credential access alert', 'HIGH', 'ACCOUNT_TAKEOVER', '10.0.1.10')"
            )
            
            # Setup investigation linking asset and vulnerability
            assets_json = json.dumps([{"asset_id": "wm-host-2", "ip_address": "10.0.1.20", "hostname": "wm-host-2"}])
            vulns_json = json.dumps([{"ip_address": "10.0.1.20", "cve_id": "CVE-TEST-9999"}])
            
            conn.execute(
                "INSERT INTO investigations (alert_id, incident_id, collected_assets, collected_vulnerabilities) "
                "VALUES (8888, 999, ?, ?)",
                (assets_json, vulns_json)
            )
            conn.commit()

    def tearDown(self):
        with get_db() as conn:
            conn.execute("DELETE FROM assets WHERE hostname LIKE 'wm-host-%'")
            conn.execute("DELETE FROM cve_feed WHERE cve_id = 'CVE-TEST-9999'")
            conn.execute("DELETE FROM incidents WHERE id = 999")
            conn.execute("DELETE FROM alerts WHERE incident_id = 999")
            conn.execute("DELETE FROM investigations WHERE alert_id = 8888")
            conn.commit()

    @patch('backend.memory.connections.get_neo4j')
    def test_predict_next_moves_fallback(self, mock_neo4j):
        mock_neo4j.return_value = None
        
        res = predict_next_moves("wm-host-1")
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["compromised_node"], "wm-host-1")
        
        predictions = res["predictions"]
        self.assertGreater(len(predictions), 0)
        self.assertEqual(predictions[0]["target_id"], "wm-host-2")
        self.assertEqual(predictions[0]["tactic"], "Privilege Escalation")

    @patch('backend.memory.connections.get_qdrant')
    def test_vulnerability_semantic_search_fallback(self, mock_qdrant):
        mock_qdrant.return_value = None
        
        res = get_similar_vulnerabilities("libtest")
        self.assertGreater(len(res), 0)
        self.assertEqual(res[0]["cve_id"], "CVE-TEST-9999")
        self.assertEqual(res[0]["severity"], "CRITICAL")
        self.assertEqual(res[0]["cvss_score"], 9.8)

    def test_attack_graph_forecasting(self):
        res = forecast_next_stages(999)
        self.assertEqual(res["incident_id"], 999)
        self.assertIn("Initial Access", res["current_stages"])
        
        forecasted = res["forecasted_stages"]
        self.assertGreater(len(forecasted), 0)
        self.assertTrue(any(f["tactic"] in ["Execution", "Persistence", "Lateral Movement"] for f in forecasted))

    def test_calculate_path_probabilities(self):
        res = calculate_path_probabilities(999)
        self.assertGreater(len(res), 0)
        self.assertEqual(res[0]["source"], "alert_8888")
        self.assertEqual(res[0]["target"], "wm-host-2")
        self.assertEqual(res[0]["probability"], 0.98)
        self.assertEqual(res[0]["type"], "exploitation")

if __name__ == "__main__":
    unittest.main()
