import time
import random
import requests
import datetime
from faker import Faker

fake = Faker()

API_URL = "http://127.0.0.1:8000/ingest"

# Realistic pool of IPs and user agents for benign traffic
BENIGN_IPS = [fake.ipv4_public() for _ in range(50)]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1"
]
ENDPOINTS = ["/api/v1/users", "/api/v1/dashboard", "/api/v1/settings", "/api/v1/products"]

def generate_benign_event():
    return {
        "timestamp": datetime.datetime.now().isoformat() + "Z",
        "event_type": random.choices(["page_view", "login", "api_call"], weights=[0.7, 0.1, 0.2])[0],
        "source_ip": random.choice(BENIGN_IPS),
        "user_id": fake.user_name(),
        "status": "success" if random.random() > 0.05 else "failed",  # 5% natural failure rate
        "device_id": fake.uuid4()[:8],
        "user_agent": random.choice(USER_AGENTS),
        "endpoint": random.choice(ENDPOINTS),
        "method": random.choice(["GET", "POST", "PUT"]),
    }

def run_simulation(eps=5):
    print(f"Starting benign telemetry generator at {eps} EPS...")
    delay = 1.0 / eps
    
    headers = {"X-API-Key": "soc-test-key-123"}
    
    try:
        while True:
            event = generate_benign_event()
            try:
                requests.post(API_URL, json=event, headers=headers, timeout=2)
                print(f"[BENIGN] Sent {event['event_type']} from {event['source_ip']}")
            except Exception as e:
                print(f"[ERROR] Connection failed: {e}")
            
            time.sleep(delay)
    except KeyboardInterrupt:
        print("\nStopping telemetry generator.")

if __name__ == "__main__":
    run_simulation(eps=2)
