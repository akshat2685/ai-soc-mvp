import sys
import os
import unittest
from unittest.mock import patch, MagicMock

# Add backend directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from backend.digital_twin.twin_simulation import simulate_containment_action
from database import get_db

class TestTwinSimulationV2(unittest.TestCase):
    def setUp(self):
        with get_db() as conn:
            # Clear mock elements from database
            conn.execute("DELETE FROM assets WHERE hostname IN ('low-crit-host', 'critical-dc', 'internal-db')")
            conn.execute("DELETE FROM user_memory WHERE user_id IN ('test-user-low', 'test-user-admin')")
            
            # Insert test records matching actual schema columns
            conn.execute(
                "INSERT INTO assets (ip_address, hostname, os, criticality, owner) "
                "VALUES ('10.0.1.100', 'low-crit-host', 'Ubuntu 22.04', 'Low', 'John Doe')"
            )
            conn.execute(
                "INSERT INTO assets (ip_address, hostname, os, criticality, owner) "
                "VALUES ('10.0.1.5', 'critical-dc', 'Windows Server 2022', 'Critical', 'Domain Admin')"
            )
            conn.execute(
                "INSERT INTO assets (ip_address, hostname, os, criticality, owner) "
                "VALUES ('10.0.1.20', 'internal-db', 'CentOS 8', 'High', 'DB Admin')"
            )
            
            conn.execute(
                "INSERT INTO user_memory (user_id, usual_country, usual_login_time, risk_profile) "
                "VALUES ('test-user-low', 'US', '09:00', 'Low')"
            )
            conn.execute(
                "INSERT INTO user_memory (user_id, usual_country, usual_login_time, risk_profile) "
                "VALUES ('test-user-admin', 'US', '08:00', 'Critical')"
            )
            conn.commit()

    def tearDown(self):
        with get_db() as conn:
            conn.execute("DELETE FROM assets WHERE hostname IN ('low-crit-host', 'critical-dc', 'internal-db')")
            conn.execute("DELETE FROM user_memory WHERE user_id IN ('test-user-low', 'test-user-admin')")
            conn.commit()

    @patch('backend.memory.connections.get_neo4j')
    def test_host_isolation_low_criticality(self, mock_neo4j):
        mock_neo4j.return_value = None
        
        res = simulate_containment_action("HOST_ISOLATION", "low-crit-host")
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["action_type"], "HOST_ISOLATION")
        self.assertEqual(res["target"], "low-crit-host")
        self.assertLess(res["disruption_score"], 0.5)
        self.assertEqual(res["recommendation"], "APPROVE_AUTO_EXECUTE")

    @patch('backend.memory.connections.get_neo4j')
    def test_host_isolation_high_criticality(self, mock_neo4j):
        mock_neo4j.return_value = None
        
        res = simulate_containment_action("HOST_ISOLATION", "critical-dc")
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["action_type"], "HOST_ISOLATION")
        self.assertGreater(res["disruption_score"], 0.7)
        self.assertEqual(res["recommendation"], "REQUIRES_APPROVAL")

    @patch('backend.memory.connections.get_neo4j')
    def test_account_disablement_low_risk(self, mock_neo4j):
        mock_neo4j.return_value = None
        
        res = simulate_containment_action("ACCOUNT_DISABLEMENT", "test-user-low")
        self.assertEqual(res["status"], "success")
        self.assertLess(res["disruption_score"], 0.6)
        self.assertEqual(res["recommendation"], "APPROVE_AUTO_EXECUTE")

    @patch('backend.memory.connections.get_neo4j')
    def test_account_disablement_admin(self, mock_neo4j):
        mock_neo4j.return_value = None
        
        res = simulate_containment_action("ACCOUNT_DISABLEMENT", "test-user-admin")
        self.assertEqual(res["status"], "success")
        self.assertGreater(res["disruption_score"], 0.7)
        self.assertEqual(res["recommendation"], "REQUIRES_APPROVAL")

    @patch('backend.memory.connections.get_neo4j')
    def test_ip_block_external(self, mock_neo4j):
        mock_neo4j.return_value = None
        
        res = simulate_containment_action("IP_BLOCK", "8.8.8.8")
        self.assertEqual(res["status"], "success")
        self.assertLess(res["disruption_score"], 0.4)
        self.assertEqual(res["recommendation"], "APPROVE_AUTO_EXECUTE")

    @patch('backend.memory.connections.get_neo4j')
    def test_ip_block_internal_critical(self, mock_neo4j):
        mock_neo4j.return_value = None
        
        res = simulate_containment_action("IP_BLOCK", "10.0.1.20")
        self.assertEqual(res["status"], "success")
        self.assertGreater(res["disruption_score"], 0.7)
        self.assertEqual(res["recommendation"], "REQUIRES_APPROVAL")

if __name__ == "__main__":
    unittest.main()
