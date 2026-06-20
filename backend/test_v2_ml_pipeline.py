import json
from purple_team.autonomous_red_agent import AutonomousRedAgent
from learning.ab_testing import ABTestingRouter
from testing.soc_benchmark import SOCBenchmarkSuite
from learning.online_updater import OnlineUpdater

def test_v2_ml_pipeline():
    print("--- Testing V2 ML Pipeline (Phases 4, 5, 6) ---")
    
    # 1. Test Red Team Injection
    print("\n[Test] Autonomous Red Agent")
    red_agent = AutonomousRedAgent()
    mock_pipeline = []
    payload_injected = red_agent.inject_attack(mock_pipeline)
    print(f"Injected Payload snippet: {payload_injected[:50]}...")
    assert len(mock_pipeline) == 1
    assert mock_pipeline[0]["is_synthetic_red_team"] is True
    
    # 2. Test A/B Testing Canary Router
    print("\n[Test] A/B Testing Router")
    router = ABTestingRouter(canary_traffic_percentage=50.0) # 50% for test visibility
    incident = {"id": "INC-1", "severity": "MEDIUM"}
    
    # Run a few times to test routing distributions
    for i in range(10):
        prod, canary = router.process_and_compare(incident)
    
    benchmarks = router.get_benchmarks()
    print(f"A/B Metrics: {json.dumps(benchmarks, indent=2)}")
    assert benchmarks["production"]["processed"] == 10
    
    # 3. Test Online Learning (Confidence Decay)
    print("\n[Test] Confidence Decay")
    updater = OnlineUpdater()
    decayed_count = updater.apply_confidence_decay()
    print(f"Decayed {decayed_count} stale rules.")
    assert decayed_count > 0

    # 4. Test SOC Benchmarks
    print("\n[Test] SOC Benchmarks")
    suite = SOCBenchmarkSuite()
    
    mock_results = [
        {"is_malicious": True, "detected": True},   # True Positive
        {"is_malicious": True, "detected": False},  # False Negative
        {"is_malicious": False, "detected": False}, # True Negative
        {"is_malicious": False, "detected": True},  # False Positive (FPR hits here)
        {"is_malicious": False, "detected": False}  # True Negative
    ]
    
    det_metrics = suite.evaluate_detection_metrics(mock_results)
    print(f"Detection Metrics: {json.dumps(det_metrics, indent=2)}")
    assert det_metrics["False_Positive_Rate"] == 33.33 # 1 FP / 3 Benign
    
    mock_incidents = [
        {"auto_resolved": True, "human_override": False},
        {"auto_resolved": True, "human_override": False},
        {"auto_resolved": False, "human_override": True},
        {"auto_resolved": True, "human_override": False}
    ]
    auto_metrics = suite.evaluate_autonomy_metrics(mock_incidents)
    print(f"Autonomy Metrics: {json.dumps(auto_metrics, indent=2)}")
    assert auto_metrics["Auto_Resolve_Rate"] == 75.0

if __name__ == "__main__":
    test_v2_ml_pipeline()
