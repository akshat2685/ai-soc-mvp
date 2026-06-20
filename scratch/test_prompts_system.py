import os
import sys
import unittest

# Add backend directory to sys.path
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend"))

from agents.prompts import PromptLoader

class TestPromptsSystem(unittest.TestCase):
    def test_constitution_loaded(self):
        """Verify that the EDYSOR Constitution is loaded and not empty."""
        const = PromptLoader.load_constitution()
        self.assertIsNotNone(const)
        self.assertTrue("CONSTITUTIONAL" in const or "PROTECT" in const)

    def test_agent_prompt_loading_with_constitution(self):
        """Verify that agent prompts successfully load and contain the constitution."""
        prompt = PromptLoader.get_prompt("supervisor", "Fallback text")
        self.assertIn("CONSTITUTIONAL", prompt)
        self.assertIn("SUPERVISOR AGENT - SYSTEM PROMPT", prompt)
        self.assertNotIn("Fallback text", prompt)

    def test_triage_prompt_loading(self):
        """Verify that the Triage Analyst prompt is loaded."""
        prompt = PromptLoader.get_prompt("threat_hunter", "Fallback text")
        self.assertIn("CONSTITUTIONAL", prompt)
        self.assertIn("Triage Analyst Agent", prompt)
        self.assertNotIn("Fallback text", prompt)

    def test_fallback_works_when_file_not_found(self):
        """Verify that fallback prompt works when no file matches and it still gets constitution."""
        prompt = PromptLoader.get_prompt("unknown_agent", "Fallback text content here")
        self.assertIn("CONSTITUTIONAL", prompt)
        self.assertIn("Fallback text content here", prompt)

if __name__ == "__main__":
    unittest.main()
