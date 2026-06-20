import json
from learning.feed_collector import FeedCollector
from memory.multi_layer import MultiLayerMemory
from world_model.graph_intelligence import GraphIntelligenceEngine

def test_cyber_immune_loop():
    print("--- Testing Continuous Intelligence Ingestion ---")
    mock_cves = [
        {"id": "CVE-2026-1122", "description": "Remote code execution in AI agent.", "mitre": ["T1566"]}
    ]
    
    processed = FeedCollector.ingest_cve_feed(mock_cves)
    print(json.dumps(processed, indent=2))
    
    print("\n--- Testing Multi-Layer Memory ---")
    memory_sys = MultiLayerMemory()
    memory_sys.working_memory["inc_001"] = {"status": "resolved", "actor": "APT29"}
    memory_sys.commit_working_to_episodic("inc_001")
    print(f"Episodic Memory Size: {len(memory_sys.episodic_memory)}")
    
    memory_sys.update_reputation("agent_red", 0.95)
    
    print("\n--- Testing Graph Intelligence Prediction ---")
    predictions = GraphIntelligenceEngine.predict_lateral_movement("Node_A")
    print(json.dumps(predictions, indent=2))
    
if __name__ == "__main__":
    test_cyber_immune_loop()
