import logging
import json
from soar.nl_parser import NaturalLanguageSOAR

logging.basicConfig(level=logging.INFO)

# Mock the LLM to bypass missing module during tests
def mock_llm_call(prompt, fallback=None):
    if "10.0.0.1" in prompt:
        return '{"action": "ISOLATE_IP", "target": "10.0.0.1", "confidence": 98, "reason": "Explicit IP isolation request"}'
    elif "evil.com" in prompt:
        return '{"action": "BLOCK_DOMAIN", "target": "evil.com", "confidence": 95, "reason": "Explicit domain block request"}'
    elif "admin_jones" in prompt:
        return '{"action": "REVOKE_USER", "target": "admin_jones", "confidence": 99, "reason": "Explicit user revoke request"}'
    else:
        return fallback

import soar.nl_parser
soar.nl_parser._call_llm = mock_llm_call

def test_nl_parser():
    print("--- Testing Natural Language SOAR Parser ---")
    
    commands = [
        "Please isolate the IP address 10.0.0.1 immediately.",
        "Block the domain evil.com",
        "Revoke access for user admin_jones",
        "What is the weather today?" # Invalid command
    ]
    
    for cmd in commands:
        print(f"\nInput: {cmd}")
        parsed = NaturalLanguageSOAR.parse_command(cmd)
        print(f"Parsed: {parsed}")
        result = NaturalLanguageSOAR.execute_parsed_command(parsed)
        print(f"Result: {result}")

if __name__ == "__main__":
    test_nl_parser()
