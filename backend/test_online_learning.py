from learning.online_learning import OnlineLearningEngine
from learning.synthetic_generator import SyntheticAttackGenerator
from federation.mesh import FederatedMesh
import json

def test_learning_pipeline():
    print("--- Testing Online Learning (Analyst Feedback) ---")
    learner = OnlineLearningEngine()
    print(f"Initial weight for prompt_injection: {learner.detection_weights['prompt_injection']}")
    
    learner.process_analyst_feedback("prompt_injection", "FALSE_POSITIVE")
    print(f"Adjusted weight after FP feedback: {learner.detection_weights['prompt_injection']}")
    
    print("\n--- Testing Synthetic Data Generation ---")
    sqli_data = SyntheticAttackGenerator.generate_sql_injection_telemetry(count=2)
    print(json.dumps(sqli_data, indent=2))
    
    print("\n--- Testing Federated Mesh (FedAvg) ---")
    mesh = FederatedMesh()
    mesh.receive_anonymized_update("peer_1", {"prompt_injection": 0.8})
    mesh.receive_anonymized_update("peer_2", {"prompt_injection": 0.9})
    
    new_weights = mesh.execute_fedavg()
    print(f"Global Weights after FedAvg: {new_weights}")

if __name__ == "__main__":
    test_learning_pipeline()
