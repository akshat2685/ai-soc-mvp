import sys
import os

# Add backend directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.agents.graph import run_soc_investigation

def main():
    print("Running Agent Investigation with Memory enrichment/learning...")
    task = "Investigate the recent spike in failed logins from IP 192.168.1.50 and check if any CVEs apply to the targeted endpoints."
    
    # Run the workflow
    result = run_soc_investigation(task)
    
    print("\n--- Agent Execution Output ---")
    for msg in result.get("messages", []):
        print(msg)
        print("-" * 30)
        
    print("\nFindings: ", result.get("findings"))
    print("\nNext step: ", result.get("next_step"))
    print("\nTest completed successfully!")

if __name__ == "__main__":
    main()
