from typing import Dict, Any

class SIEMParser:
    """
    Normalizes proprietary SIEM/EDR data formats into the internal EDYSOR-X TelemetryLog schema.
    """
    
    @staticmethod
    def parse_splunk(payload: Dict[str, Any]) -> Dict[str, Any]:
        """Maps a Splunk Webhook JSON payload to TelemetryLog."""
        # Splunk typically sends data inside a 'result' object
        result = payload.get("result", payload)
        
        return {
            "source_ip": result.get("src_ip", "0.0.0.0"),
            "destination_ip": result.get("dest_ip", "0.0.0.0"),
            "event_type": result.get("sourcetype", "splunk_log"),
            "severity": "HIGH" if "critical" in str(result.get("_raw", "")).lower() else "MEDIUM",
            "user_id": result.get("user", "system"),
            "endpoint": result.get("host", "unknown_host"),
            "payload_data": result.get("_raw", str(result)),
            "protocol": result.get("protocol", "TCP")
        }

    @staticmethod
    def parse_crowdstrike(payload: Dict[str, Any]) -> Dict[str, Any]:
        """Maps a CrowdStrike Falcon Webhook JSON payload to TelemetryLog."""
        event = payload.get("event", payload)
        
        return {
            "source_ip": event.get("LocalIP", "0.0.0.0"),
            "destination_ip": event.get("RemoteIP", "0.0.0.0"),
            "event_type": "crowdstrike_" + event.get("DetectName", "alert"),
            "severity": "CRITICAL" if event.get("Severity", 0) > 3 else "HIGH",
            "user_id": event.get("UserName", "system"),
            "endpoint": event.get("ComputerName", "unknown_host"),
            "payload_data": event.get("DetectDescription", str(event)),
            "protocol": "TCP"
        }
