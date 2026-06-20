import sys
from unittest.mock import MagicMock
sys.modules['numpy'] = MagicMock()

from learning.cloud_data_lake import CloudDataLake
from detectors.isolation_forest import BehavioralAnomalyDetector

def test_phase3():
    print("--- Testing V2 Evolution Phase 3 ---")
    
    # 1. Test Cloud Data Lake (Mock Mode)
    print("\n[Test] Cloud Data Lake Export")
    data_lake = CloudDataLake(bucket_name="test-bucket")
    
    # Force mock mode for test environment without credentials
    data_lake.use_mock = True 
    
    mock_batch = [
        {"incident_id": "INC-1", "label": "malicious", "attack_type": "SQLi"},
        {"incident_id": "INC-2", "label": "benign", "attack_type": "None"}
    ]
    
    result = data_lake.export_training_batch(mock_batch, "labeled_incidents")
    print(f"Export Result: {result}")
    assert "gs://test-bucket/labeled_incidents/" in result
    
    # 2. Test Isolation Forest Baseline
    print("\n[Test] Behavioral Anomaly Detector (Isolation Forest)")
    detector = BehavioralAnomalyDetector()
    
    # Force mock if sklearn isn't installed in the test env
    event_context_malicious = {"destination_ip": "185.15.5.5"}
    score_malicious = detector.score_event(features=[9.9, 8.8], event_context=event_context_malicious)
    print(f"Malicious Event Score: {score_malicious}")
    assert score_malicious["is_anomaly"] is True
    
    event_context_benign = {"destination_ip": "8.8.8.8"}
    score_benign = detector.score_event(features=[0.1, 0.2], event_context=event_context_benign)
    print(f"Benign Event Score: {score_benign}")
    assert score_benign["is_anomaly"] is False

if __name__ == "__main__":
    test_phase3()
