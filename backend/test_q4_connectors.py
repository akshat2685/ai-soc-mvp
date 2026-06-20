import json
from integrations.parsers import SIEMParser

def test_siem_connectors():
    print("--- Testing Universal SIEM Connectors ---")
    
    # 1. Test Splunk Webhook
    splunk_payload = {
        "result": {
            "src_ip": "192.168.1.55",
            "dest_ip": "10.0.0.99",
            "sourcetype": "splunk_firewall_log",
            "_raw": "Connection reset by peer. Critical security exception.",
            "user": "jdoe",
            "host": "web-server-01",
            "protocol": "HTTPS"
        }
    }
    print("\nSending mock Splunk Payload...")
    normalized_splunk = SIEMParser.parse_splunk(splunk_payload)
    print(json.dumps(normalized_splunk, indent=2))

    # 2. Test CrowdStrike Webhook
    crowdstrike_payload = {
        "event": {
            "LocalIP": "10.1.1.200",
            "RemoteIP": "185.15.5.5",
            "DetectName": "RansomwareBehavior",
            "Severity": 5,
            "UserName": "svc_account",
            "ComputerName": "db-server-02",
            "DetectDescription": "High entropy file encryption detected in user directory."
        }
    }
    print("\nSending mock CrowdStrike Payload...")
    normalized_cs = SIEMParser.parse_crowdstrike(crowdstrike_payload)
    print(json.dumps(normalized_cs, indent=2))

if __name__ == "__main__":
    test_siem_connectors()
