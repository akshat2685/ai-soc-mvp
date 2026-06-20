import logging
import time
import json
from typing import Dict, Any

logger = logging.getLogger(__name__)

class IoTEdgeAgent:
    """
    Sub-100ms Edge Detection Agent (Part 4).
    Designed to be deployed via K3s (Lightweight Kubernetes) to IoT endpoints (e.g., Raspberry Pi, Industrial Routers).
    Analyzes syslogs locally and only forwards confirmed anomalies to the central EDYSOR-X cluster to save bandwidth.
    """
    def __init__(self, edge_id: str, central_cluster_url: str):
        self.edge_id = edge_id
        self.central_cluster_url = central_cluster_url
        self.local_rules = ["sudo rm -rf", "nmap", "nc -e", "chmod 777"]

    def analyze_local_log(self, log_line: str) -> bool:
        """Sub-100ms local heuristic analysis."""
        for rule in self.local_rules:
            if rule in log_line.lower():
                return True
        return False

    def forward_to_central(self, log_line: str, severity: str):
        """Pushes only the critical anomalous logs to the main cluster."""
        payload = {
            "edge_id": self.edge_id,
            "timestamp": time.time(),
            "log": log_line,
            "severity": severity,
            "action_taken": "FORWARDED"
        }
        logger.warning(f"[EDGE AGENT {self.edge_id}] Forwarding critical anomaly to {self.central_cluster_url}: {json.dumps(payload)}")
        # In prod: requests.post(self.central_cluster_url, json=payload)

    def run_tail_loop(self):
        """Simulates `tail -f /var/log/syslog` on an IoT device."""
        logger.info(f"[EDGE AGENT {self.edge_id}] Starting local log monitoring...")
        # Simulated log ingestion
        test_logs = [
            "systemd: Started Cron daemon.",
            "sshd: Accepted publickey for user admin",
            "bash: sudo rm -rf /etc/kubernetes/", # Anomaly
            "kernel: eth0 link up"
        ]
        
        for log in test_logs:
            start_time = time.time()
            is_anomalous = self.analyze_local_log(log)
            process_time_ms = (time.time() - start_time) * 1000
            
            if is_anomalous:
                logger.warning(f"[EDGE AGENT {self.edge_id}] Local anomaly detected in {process_time_ms:.2f}ms")
                self.forward_to_central(log, "CRITICAL")
                
if __name__ == "__main__":
    agent = IoTEdgeAgent("edge-router-01", "https://edysor.hq.internal/api/ingest")
    agent.run_tail_loop()
