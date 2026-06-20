import sys
from unittest.mock import MagicMock
sys.modules['redis'] = MagicMock()

from integrations.threat_fusion import ThreatFusionEngine
from autonomous.autonomous_engine import AutonomousResponseEngine

def test_v2_upgrades():
    print("--- Testing V2 Evolution Upgrades ---")
    
    # 1. Test Threat Fusion
    fusion_engine = ThreatFusionEngine()
    print("\n[Test] Threat Fusion Engine (MISP, VT, OTX, Abuse.ch)")
    
    malicious_ioc = "185.15.5.5"
    result = fusion_engine.calculate_fused_confidence(malicious_ioc)
    print(f"IOC: {malicious_ioc}")
    print(f"Fused Score: {result['fused_confidence']}%")
    print(f"Is Malicious: {result['is_malicious']}")
    assert result['fused_confidence'] > 90.0, "Fused confidence should be extremely high."
    
    benign_ioc = "8.8.8.8"
    result_benign = fusion_engine.calculate_fused_confidence(benign_ioc)
    print(f"\nIOC: {benign_ioc}")
    print(f"Fused Score: {result_benign['fused_confidence']}%")
    print(f"Is Malicious: {result_benign['is_malicious']}")
    assert result_benign['fused_confidence'] < 20.0, "Fused confidence should be low."

    # 2. Test Autonomous Response Tiers
    print("\n[Test] Autonomous Response Engine Tiers")
    
    # Test Tier 0 (Auto-Block)
    incident_0 = {"attacker_ip": malicious_ioc}
    resp_0 = AutonomousResponseEngine.evaluate_and_respond(incident_0, confidence=98.0, severity="CRITICAL")
    print(f"Tier 0 Response: {resp_0}")
    assert "Blocked IP" in resp_0
    
    # Test Tier 1 (Auto-Investigate)
    incident_1 = {"attacker_ip": "10.0.0.5"}
    resp_1 = AutonomousResponseEngine.evaluate_and_respond(incident_1, confidence=88.0, severity="HIGH")
    print(f"Tier 1 Response: {resp_1}")
    assert "Snapshotted" in resp_1
    
    # Test Tier 2 (Escalate)
    incident_2 = {"attacker_ip": "192.168.1.100"}
    resp_2 = AutonomousResponseEngine.evaluate_and_respond(incident_2, confidence=65.0, severity="LOW")
    print(f"Tier 2 Response: {resp_2}")
    assert "Escalated" in resp_2

if __name__ == "__main__":
    test_v2_upgrades()
