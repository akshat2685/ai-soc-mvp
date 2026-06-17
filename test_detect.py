import os
import sys
sys.path.append("/app/backend")

from database import get_db
from detectors.credential_stuffing import CredentialStuffingDetector

def main():
    print("Testing Credential Stuffing Detector")
    detector = CredentialStuffingDetector()
    
    with get_db() as conn:
        cur = conn.execute("SELECT DISTINCT source_ip FROM logs WHERE event_type = 'login' AND status = 'failed'")
        ips = [row["source_ip"] for row in cur.fetchall()]
        
    print(f"Found IPs with failed logins: {ips}")
    
    for ip in ips:
        print(f"Testing IP: {ip}")
        result = detector.detect(ip, None, "unknown")
        if result:
            print(f"ALERT! {result.attack_type} on {ip} with score {result.confidence_score}")
        else:
            print(f"No alert for {ip}")

if __name__ == "__main__":
    main()
