import time
import json
from resilience.chaos_monkey import ChaosMonkey
from resilience.confidential_enclave import ConfidentialEnclave

def mock_sensitive_processing(secret_data):
    # This represents something happening inside the enclave
    return f"Processed data length: {len(secret_data)}"

def test_resilience():
    print("--- Testing Chaos Monkey ---")
    try:
        print("Triggering random fault (forced probability=1.0)...")
        ChaosMonkey.trigger_random_fault(probability=1.0)
    except ConnectionError as e:
        print(f"Caught expected Chaos Monkey error: {e}")
        
    print("\n--- Testing Confidential Enclave ---")
    sensitive_context = {
        "user_hash": "a1b2c3d4",
        "session_token": "SUPER_SECRET_TOKEN",
        "decrypted_payload": "password123"
    }
    
    result = ConfidentialEnclave.execute_in_enclave(sensitive_context, mock_sensitive_processing, sensitive_context)
    print(f"Enclave Result: {result}")
    
if __name__ == "__main__":
    test_resilience()
