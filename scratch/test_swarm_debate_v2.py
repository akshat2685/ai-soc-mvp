import sys
import os
import unittest

# Add backend directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from backend.agents.swarm_debate import run_swarm_debate

class TestSwarmDebateV2(unittest.TestCase):
    def test_debate_true_positive_consensus(self):
        findings = {
            "threat_hunter": {
                "verdict": "TRUE_POSITIVE",
                "confidence": 0.90
            },
            "root_cause": {
                "vulnerabilities": [{"cve": "CVE-2023-38545"}]
            },
            "malware_analysis": "Powershell command executes payload extraction from remote server."
        }
        res = run_swarm_debate(findings)
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["verdict"], "TRUE_POSITIVE")
        self.assertGreaterEqual(res["confidence"], 0.8)
        self.assertEqual(len(res["debate_transcript"]), 4) # 3 personas + consensus note
        
        # Check all personas are present in transcript
        self.assertTrue(any("Threat Hunter" in line for line in res["debate_transcript"]))
        self.assertTrue(any("Malware Analyst" in line for line in res["debate_transcript"]))
        self.assertTrue(any("Root Cause Analyst" in line for line in res["debate_transcript"]))

    def test_debate_false_positive_by_voting(self):
        # Threat Hunter says False Positive, Malware Analyst says False Positive (benign string)
        findings = {
            "threat_hunter": {
                "verdict": "FALSE_POSITIVE",
                "confidence": 0.85
            },
            "root_cause": {
                "vulnerabilities": []
            },
            "malware_analysis": "Benign. Safe git command execution."
        }
        res = run_swarm_debate(findings)
        self.assertEqual(res["status"], "success")
        # 3 votes: Hunter (FP), Malware (FP), Root Cause (FP since vulns empty & hunter FP)
        self.assertEqual(res["verdict"], "FALSE_POSITIVE")
        self.assertEqual(res["confidence"], 0.7833) # Average of (0.85, 0.80, 0.70)
        self.assertTrue(any("Consensus resolved: FALSE_POSITIVE" in line for line in res["debate_transcript"]))

if __name__ == "__main__":
    unittest.main()
