import json
from xai.engine import XAIEngine

def test_xai():
    print("Testing Feature Attribution...")
    features = {
        "login_failures": 15.0,
        "bytes_out": 50000.0,
        "bytes_in": 120.0,
        "success_rate": -0.8
    }
    
    attributions = XAIEngine.generate_feature_attribution(features)
    for a in attributions:
        print(f"  {a.feature_name}: {a.importance_score} ({a.impact_direction})")
        
    print("\nTesting LLM Explanation Generation...")
    
    decision = "TRUE_POSITIVE - Block IP 192.168.1.100 and isolate Host A."
    context = {"swarm_confidence": 0.92, "swarm_verdict": "TRUE_POSITIVE"}
    trace = [
        "Planner: Task is to investigate login anomalies.",
        "Threat Hunter: Found 15 failed logins followed by large outbound data transfer.",
        "Executive: High confidence of credential stuffing leading to exfiltration. Consensus reached."
    ]
    
    explanation = XAIEngine.generate_explanation(decision, context, trace)
    print("\nXAI Output:")
    print(json.dumps(explanation.model_dump(), indent=2))

if __name__ == "__main__":
    test_xai()
