import os
import sys
import unittest

# Add backend directory to sys.path
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend"))

from database import init_db, get_db
from agents.dpo_alignment import generate_dpo_pair, calculate_dpo_loss
from purple_team.orchestrator import run_weekly_red_team_cycle, generate_adversarial_scenario
from learning.federated import FederatedLearningCoordinator

class TestAlignmentAndRedTeamCycles(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()

    def test_dpo_loss_calculator(self):
        """Verify DPO loss math converges correctly."""
        loss_high = calculate_dpo_loss(chosen_prob=0.9, rejected_prob=0.1)
        loss_low = calculate_dpo_loss(chosen_prob=0.5, rejected_prob=0.5)
        # Higher margin = lower loss
        self.assertLess(loss_high, loss_low)

    def test_dpo_preference_generation(self):
        """Verify DPO variant generation writes to preference DB."""
        res = generate_dpo_pair("threat_hunter", "Test prompt")
        self.assertIn("chosen", res)
        self.assertIn("rejected", res)
        self.assertGreaterEqual(res["chosen_score"], res["rejected_score"])
        
        # Verify db insert
        with get_db() as conn:
            cur = conn.execute("SELECT COUNT(*) as c FROM dpo_preference_data WHERE agent_name = 'threat_hunter'")
            self.assertGreater(cur.fetchone()["c"], 0)

    def test_weekly_red_team_cycle_days(self):
        """Verify Red Team cycle runner daily deliverables."""
        mon = run_weekly_red_team_cycle("Monday")
        self.assertEqual(mon["day"], "Monday")
        self.assertEqual(mon["scenarios_count"], 50)
        self.assertIn("payload", mon["sample_scenario"])
        
        tue = run_weekly_red_team_cycle("Tuesday")
        self.assertEqual(tue["day"], "Tuesday")
        self.assertIn("precision", tue)
        
        wed = run_weekly_red_team_cycle("Wednesday")
        self.assertEqual(wed["day"], "Wednesday")
        self.assertGreater(wed["missed_gaps_count"], 0)

    def test_federated_learning_privacy(self):
        """Verify federated anonymization and FedAvg noise math."""
        coordinator = FederatedLearningCoordinator(privacy_epsilon=1.0)
        
        # 1. Anonymization check
        sample_inc = {
            "title": "Alert on 192.168.1.100 by admin",
            "attacker_ip": "192.168.1.100",
            "user_id": "admin"
        }
        anon = coordinator.anonymize_incident_data(sample_inc)
        self.assertEqual(anon["attacker_ip"], "[STRIPPED]")
        self.assertEqual(anon["user_id"], "[STRIPPED]")
        self.assertNotIn("192.168.1.100", anon["title"])
        self.assertIn("[MASKED_IP]", anon["title"])

        # 2. Sync cycle
        sync_res = coordinator.trigger_federated_sync(epoch=1)
        self.assertEqual(sync_res["epoch"], 1)
        self.assertEqual(sync_res["status"], "COMPLETED")
        self.assertEqual(len(sync_res["global_weights"]), 5)

if __name__ == "__main__":
    unittest.main()
