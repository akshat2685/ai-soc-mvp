import time
import json
import random
import threading
import httpx
from datetime import datetime, timezone
import os

SOC_URL = os.environ.get("SOC_URL", "http://127.0.0.1:8000/ingest")
API_KEY = "dummy-api-key"

def send_log(log: dict):
    try:
        httpx.post(SOC_URL, json=log, headers={"X-API-Key": API_KEY}, timeout=2.0)
    except Exception as e:
        pass

def simulate_ddos(count=1000):
    print(f"Simulating DDoS ({count} requests)...")
    for _ in range(count):
        ip = f"{random.randint(1,200)}.{random.randint(1,200)}.{random.randint(1,200)}.{random.randint(1,200)}"
        log = {
            "event_type": "api_call",
            "source_ip": ip,
            "status": "success",
            "endpoint": "/api/v1/heavy-query",
            "method": "GET",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) LOIC/1.0"
        }
        send_log(log)

def simulate_brute_force(count=500):
    print(f"Simulating Brute Force ({count} requests)...")
    ip = "192.168.1.55"  # Attacker IP
    for _ in range(count):
        log = {
            "event_type": "login",
            "source_ip": ip,
            "status": "failed",
            "endpoint": "/api/v1/auth/login",
            "method": "POST",
            "user_id": f"admin_{random.randint(1,100)}",
            "user_agent": "Hydra/9.0"
        }
        send_log(log)

def simulate_botnet(count=300):
    print(f"Simulating Botnet C2 ({count} requests)...")
    ips = [f"10.0.0.{i}" for i in range(10, 50)]
    for _ in range(count):
        log = {
            "event_type": "api_call",
            "source_ip": random.choice(ips),
            "status": "success",
            "endpoint": "/beacon",
            "method": "POST",
            "device_id": "mirai-variant-88",
            "user_agent": "curl/7.68.0"
        }
        send_log(log)

def simulate_port_scan(count=200):
    print(f"Simulating Port/Path Scan ({count} requests)...")
    ip = "45.33.22.11"
    paths = ["/admin", "/.env", "/wp-login.php", "/config.json", "/backup.zip"]
    for _ in range(count):
        log = {
            "event_type": "page_view",
            "source_ip": ip,
            "status": "error",
            "endpoint": random.choice(paths),
            "method": "GET",
            "user_agent": "Nmap/7.92"
        }
        send_log(log)

def simulate_web_attacks(count=100):
    print(f"Simulating Web Attacks ({count} requests)...")
    ip = "8.8.8.8"
    payloads = [
        "/api/users?id=1' OR '1'='1",
        "/search?q=<script>alert(1)</script>",
        "/download?file=../../../../etc/passwd"
    ]
    for _ in range(count):
        log = {
            "event_type": "api_call",
            "source_ip": ip,
            "status": "error",
            "endpoint": random.choice(payloads),
            "method": "GET",
            "user_agent": "Mozilla/5.0"
        }
        send_log(log)

if __name__ == "__main__":
    print("Starting CICIDS Bootstrapper...")
    # Using 2500 logs total as agreed
    t1 = threading.Thread(target=simulate_ddos, args=(1000,))
    t2 = threading.Thread(target=simulate_brute_force, args=(500,))
    t3 = threading.Thread(target=simulate_botnet, args=(500,))
    t4 = threading.Thread(target=simulate_port_scan, args=(300,))
    t5 = threading.Thread(target=simulate_web_attacks, args=(200,))

    threads = [t1, t2, t3, t4, t5]
    for t in threads: t.start()
    for t in threads: t.join()

    print("Bootstrapping complete! 2,500 malicious logs injected.")
