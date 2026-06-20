import sys
import os
import unittest
from unittest.mock import patch

# Add backend directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from backend.causal_ai.causal_engine import fit_causal_model, calculate_causal_effect
from database import get_db

class TestCausalEngineV2(unittest.TestCase):
    def setUp(self):
        with get_db() as conn:
            # Clear and seed alerts for Bayesian conditional probability test
            conn.execute("DELETE FROM alerts WHERE incident_id = 9991")
            conn.execute(
                "INSERT INTO alerts (id, incident_id, timestamp, title, severity, attack_type, attacker_ip) "
                "VALUES (7771, 9991, '2026-06-19T12:00:00Z', 'Stuffing Alert', 'HIGH', 'CREDENTIAL_STUFFING', '10.0.1.1')"
            )
            conn.execute(
                "INSERT INTO alerts (id, incident_id, timestamp, title, severity, attack_type, attacker_ip) "
                "VALUES (7772, 9991, '2026-06-19T12:05:00Z', 'Takeover Alert', 'HIGH', 'ACCOUNT_TAKEOVER', '10.0.1.1')"
            )
            conn.commit()

    def tearDown(self):
        with get_db() as conn:
            conn.execute("DELETE FROM alerts WHERE incident_id = 9991")
            conn.commit()

    def test_fit_causal_model(self):
        alert_sequence = [
            {"attack_type": "CREDENTIAL_STUFFING"},
            {"attack_type": "ACCOUNT_TAKEOVER"},
            {"attack_type": "COUPON_ABUSE"}
        ]
        res = fit_causal_model(alert_sequence)
        self.assertEqual(res["status"], "success")
        self.assertEqual(len(res["nodes"]), 3)
        self.assertEqual(len(res["edges"]), 2)
        self.assertEqual(res["edges"][0]["source"], "CREDENTIAL_STUFFING")
        self.assertEqual(res["edges"][0]["target"], "ACCOUNT_TAKEOVER")

    def test_calculate_causal_effect_baseline(self):
        # Test default static baseline mapping
        effect = calculate_causal_effect("CREDENTIAL_STUFFING", "ACCOUNT_TAKEOVER")
        self.assertGreaterEqual(effect, 0.5)

    def test_calculate_causal_effect_unknown(self):
        # Unrelated alert sequence should have very low causal effect
        effect = calculate_causal_effect("BOT_SCRAPING", "OTP_ABUSE")
        self.assertLess(effect, 0.4)

if __name__ == "__main__":
    unittest.main()
