import sys
import os
import unittest

# Add backend directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from backend.purple_team.rule_validator import validate_detection_rules

class TestRuleValidatorV2(unittest.TestCase):
    def test_rule_passed_fp_check(self):
        rules = [
            {
                "name": "Detect Mimikatz Credential Dumping",
                "type": "YARA",
                "content": 'rule mimikatz { strings: $a = "mimikatz" $b = "sekurlsa" condition: any of them }'
            },
            {
                "name": "Detect Shadow Copy Deletion",
                "type": "SIGMA",
                "content": 'title: Shadow Copy Deletion\nlogsource:\n  product: windows\ndetection:\n  selection:\n    CommandLine|contains: "vssadmin.exe delete shadows"'
            }
        ]
        res = validate_detection_rules(rules)
        self.assertEqual(len(res), 2)
        
        self.assertEqual(res[0]["rule_name"], "Detect Mimikatz Credential Dumping")
        self.assertEqual(res[0]["status"], "PASSED_FP_CHECK")
        self.assertEqual(res[0]["false_positive_rate"], 0.0)
        
        self.assertEqual(res[1]["rule_name"], "Detect Shadow Copy Deletion")
        self.assertEqual(res[1]["status"], "PASSED_FP_CHECK")
        self.assertEqual(res[1]["false_positive_rate"], 0.0)

    def test_rule_failed_fp_check(self):
        rules = [
            {
                "name": "Detect Git Activity (Noisy)",
                "type": "YARA",
                "content": 'rule noisy_git { strings: $a = "git commit" condition: $a }'
            },
            {
                "name": "Detect Apt Get Updates (Noisy)",
                "type": "SIGMA",
                "content": 'title: Apt Get Update\ndetection:\n  selection:\n    CommandLine|contains: "apt-get"'
            }
        ]
        res = validate_detection_rules(rules)
        self.assertEqual(len(res), 2)
        
        self.assertEqual(res[0]["rule_name"], "Detect Git Activity (Noisy)")
        self.assertEqual(res[0]["status"], "FAILED_FP_CHECK")
        self.assertGreater(res[0]["false_positive_rate"], 0.0)
        
        self.assertEqual(res[1]["rule_name"], "Detect Apt Get Updates (Noisy)")
        self.assertEqual(res[1]["status"], "FAILED_FP_CHECK")
        self.assertGreater(res[1]["false_positive_rate"], 0.0)

if __name__ == "__main__":
    unittest.main()
