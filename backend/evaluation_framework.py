import json
import time
from investigation_engine import analyze_alert
from database import get_db

EVALUATION_DATASET = [
    {
        "test_id": "T001",
        "description": "Benign Admin Login",
        "alert": {"title": "Multiple Failed Logins", "severity": "MEDIUM", "attack_type": "BRUTE_FORCE", "attacker_ip": "10.0.0.50"},
        "expected_verdict": "FALSE_POSITIVE"
    },
    {
        "test_id": "T002",
        "description": "Actual Credential Stuffing",
        "alert": {"title": "High Volume Login Failures", "severity": "HIGH", "attack_type": "CREDENTIAL_STUFFING", "attacker_ip": "45.33.12.9"},
        "expected_verdict": "TRUE_POSITIVE"
    },
    {
        "test_id": "T003",
        "description": "Log4j RCE Attempt",
        "alert": {"title": "JNDI Lookup Pattern", "severity": "CRITICAL", "attack_type": "REMOTE_CODE_EXECUTION", "attacker_ip": "185.15.55.2"},
        "expected_verdict": "TRUE_POSITIVE"
    }
]

def run_evaluation():
    print("=== SOC AI Evaluation Framework ===")
    results = []
    
    for test in EVALUATION_DATASET:
        print(f"Running Test {test['test_id']}: {test['description']}")
        start_time = time.time()
        
        # Simulate an alert investigation
        try:
            analysis = analyze_alert(
                test["alert"]["title"],
                test["alert"]["severity"],
                test["alert"]["attack_type"],
                test["alert"]["attacker_ip"],
                "test_fingerprint",
                ["user1"]
            )
            predicted_verdict = analysis.get("verdict", "PENDING")
        except Exception as e:
            predicted_verdict = f"ERROR: {e}"
            
        latency = time.time() - start_time
        
        match = predicted_verdict == test["expected_verdict"]
        results.append({
            "test_id": test["test_id"],
            "expected": test["expected_verdict"],
            "predicted": predicted_verdict,
            "match": match,
            "latency_sec": round(latency, 2)
        })
        
    # Print Summary
    print("\n=== Evaluation Results ===")
    matches = sum(1 for r in results if r["match"])
    total = len(results)
    accuracy = (matches / total) * 100
    
    for r in results:
        status = "[PASS]" if r["match"] else "[FAIL]"
        print(f"{r['test_id']} - {status} (Expected: {r['expected']}, Got: {r['predicted']} | {r['latency_sec']}s)")
        
    print(f"\nOverall Accuracy: {accuracy:.1f}%")
    return results

if __name__ == "__main__":
    run_evaluation()
