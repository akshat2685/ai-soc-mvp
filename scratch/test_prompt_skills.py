import sys
import os

# Add backend to path
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend"))

from agents.prompts import PromptLoader

def main():
    prompt = PromptLoader.get_prompt("threat_hunter", "fallback")
    print("--- THREAT HUNTER PROMPT ---")
    print(prompt)

if __name__ == "__main__":
    main()
