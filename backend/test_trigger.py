import os
import sys

from database import get_db
from detectors.credential_stuffing import CredentialStuffingDetector
from detection import trigger_incident

def main():
    print("Testing trigger_incident")
    detector = CredentialStuffingDetector()
    
    ip = '192.168.50.10'
    result = detector.detect(ip, None, "unknown")
    if result:
        print(f"ALERT! {result.attack_type} on {ip} with score {result.confidence_score}")
        try:
            trigger_incident(
                title=result.title,
                attack_type=result.attack_type,
                severity=result.severity,
                attacker_ip=result.source_ip,
                events=result.events,
                device_fingerprint=result.device_fingerprint,
                confidence_score=result.confidence_score,
                evidence_citations=result.evidence_citations,
                background_tasks=None
            )
            print("Successfully triggered incident!")
        except Exception as e:
            print(f"Failed to trigger incident: {e}")
    else:
        print(f"No alert for {ip}")

if __name__ == "__main__":
    main()
