"""AI SOC Attack Simulator — YAML-driven configurable attack scenarios.

Usage:
    python simulate_attacks.py                          # Run default scenarios
    python simulate_attacks.py --scenario evasive       # Run evasive scenarios
    python simulate_attacks.py --scenario distributed   # Run distributed scenarios
    python simulate_attacks.py --scenario mixed         # Run mixed traffic
    python simulate_attacks.py --scenario all           # Run all scenarios
    python simulate_attacks.py --list                   # List available scenarios
"""
import requests
import time
import random
import json
import sys
import os

API_URL = "http://127.0.0.1:8000/ingest"

# ══════════════════════════════════════════════════════════════
#  SCENARIO DEFINITIONS
# ══════════════════════════════════════════════════════════════

SCENARIOS = {
    "default": {
        "name": "Default Attack Suite",
        "description": "Basic attack patterns: credential stuffing, OTP abuse, bot scraping, ATO, coupon fraud",
        "attacks": [
            {
                "name": "Credential Stuffing",
                "type": "burst",
                "count": 6,
                "interval": 0.05,
                "source_ip": "192.168.1.100",
                "event_type": "login",
                "status": "failed",
                "device_id": "unknown-device",
                "user_agent": "Mozilla/5.0",
                "endpoint": "/api/v1/auth/login",
                "method": "POST",
                "user_id_pattern": "admin{i}",
            },
            {
                "name": "OTP Pumping",
                "type": "burst",
                "count": 4,
                "interval": 0.05,
                "source_ip": "203.0.113.45",
                "event_type": "otp_request",
                "status": "success",
                "device_id": "bot-net-2",
                "user_agent": "Mozilla/5.0",
                "endpoint": "/api/v1/auth/otp/send",
                "method": "POST",
            },
            {
                "name": "Bot Scraping",
                "type": "burst",
                "count": 12,
                "interval": 0.02,
                "source_ip": "10.0.0.77",
                "event_type": "page_view",
                "status": "success",
                "user_agent": "python-requests/2.28.0",
                "endpoint_pattern": "/api/v1/products/{i}",
                "method": "GET",
            },
            {
                "name": "Account Takeover",
                "type": "ato",
                "failed_count": 4,
                "source_ip": "172.16.0.55",
                "target_user": "victim_user_42",
                "device_id": "new-device-xyz",
                "user_agent": "Mozilla/5.0 Chrome/120",
                "endpoint": "/api/v1/auth/login",
            },
            {
                "name": "Coupon Abuse",
                "type": "burst",
                "count": 4,
                "interval": 0.05,
                "source_ip": "198.51.100.22",
                "event_type": "coupon_apply",
                "status": "success",
                "user_id": "coupon_abuser_99",
                "user_agent": "Mozilla/5.0",
                "endpoint": "/api/v1/checkout/coupon",
                "method": "POST",
            },
        ],
    },
    "evasive": {
        "name": "Evasive Attack Patterns",
        "description": "Slow-rate credential stuffing, IP rotation, and UA randomization to evade detection",
        "attacks": [
            {
                "name": "Slow-Rate Credential Stuffing",
                "type": "slow_rate",
                "count": 8,
                "interval": 2.0,  # 2 seconds between attempts (slow)
                "source_ip": "192.168.50.10",
                "event_type": "login",
                "status": "failed",
                "user_id_pattern": "user_{i}",
                "endpoint": "/api/v1/auth/login",
                "method": "POST",
                "rotate_user_agent": True,
            },
            {
                "name": "IP-Rotating Credential Stuffing",
                "type": "ip_rotation",
                "count": 6,
                "interval": 0.1,
                "ip_pattern": "192.168.2.{ip}",
                "ip_range": [10, 16],
                "event_type": "login",
                "status": "failed",
                "user_id": "target_admin",
                "device_id": "same-device-fingerprint",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "endpoint": "/api/v1/auth/login",
                "method": "POST",
                "headers": {"Accept-Language": "en-US", "Accept-Encoding": "gzip, deflate"},
            },
            {
                "name": "Header-Preserving Rotation",
                "type": "ip_rotation",
                "count": 5,
                "interval": 0.1,
                "ip_pattern": "10.10.{ip}.1",
                "ip_range": [1, 6],
                "event_type": "login",
                "status": "failed",
                "user_id": "admin_account",
                "device_id": "bot-tool-v2",
                "user_agent": "curl/7.68.0",
                "endpoint": "/api/v1/auth/login",
                "method": "POST",
                "headers": {"X-Custom-Header": "attack-tool-v2", "Accept": "*/*"},
            },
        ],
    },
    "distributed": {
        "name": "Distributed Botnet Attack",
        "description": "Same account targeted from many IPs simulating a botnet",
        "attacks": [
            {
                "name": "Distributed Credential Stuffing — 15 IPs",
                "type": "distributed",
                "target_user": "high_value_target",
                "ip_count": 15,
                "attempts_per_ip": 2,
                "interval": 0.05,
                "event_type": "login",
                "status": "failed",
                "endpoint": "/api/v1/auth/login",
                "method": "POST",
            },
            {
                "name": "Distributed OTP Abuse",
                "type": "distributed",
                "target_user": "otp_target_user",
                "ip_count": 8,
                "attempts_per_ip": 1,
                "interval": 0.1,
                "event_type": "otp_request",
                "status": "success",
                "endpoint": "/api/v1/auth/otp/send",
                "method": "POST",
            },
        ],
    },
    "mixed": {
        "name": "Mixed Legitimate + Malicious Traffic",
        "description": "90% legitimate traffic interspersed with 10% malicious to test false positive rates",
        "attacks": [
            {
                "name": "Mixed Traffic Simulation",
                "type": "mixed",
                "total_requests": 50,
                "malicious_ratio": 0.15,
                "legitimate_patterns": [
                    {"event_type": "login", "status": "success", "endpoint": "/api/v1/auth/login"},
                    {"event_type": "page_view", "status": "success", "endpoint": "/api/v1/products/1"},
                    {"event_type": "api_call", "status": "success", "endpoint": "/api/v1/users/profile"},
                    {"event_type": "order", "status": "success", "endpoint": "/api/v1/checkout"},
                ],
                "malicious_patterns": [
                    {"event_type": "login", "status": "failed", "endpoint": "/api/v1/auth/login", "source_ip": "192.168.99.1"},
                    {"event_type": "otp_request", "status": "success", "endpoint": "/api/v1/auth/otp/send", "source_ip": "192.168.99.2"},
                ],
            },
        ],
    },
}

# ══════════════════════════════════════════════════════════════
#  USER AGENT POOL (for rotation)
# ══════════════════════════════════════════════════════════════

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
    "python-requests/2.31.0",
    "curl/8.1.2",
    "Go-http-client/1.1",
]

LEGIT_USER_AGENTS = USER_AGENTS[:5]  # Browser UAs only
LEGIT_IPS = [f"10.20.30.{i}" for i in range(1, 20)]
LEGIT_USERS = [f"legit_user_{i}" for i in range(1, 30)]

# ══════════════════════════════════════════════════════════════
#  SIMULATOR ENGINE
# ══════════════════════════════════════════════════════════════

class AttackSimulator:

    def __init__(self, api_url=API_URL):
        self.api_url = api_url
        self.stats = {"sent": 0, "errors": 0}

    def send_log(self, payload: dict):
        """Send a single log entry to the /ingest endpoint."""
        try:
            headers = {"X-API-Key": "shieldai_dev_api_key_2026"}
            resp = requests.post(self.api_url, json=payload, headers=headers, timeout=5)
            if resp.status_code == 200:
                self.stats["sent"] += 1
            elif resp.status_code == 429:
                print(f"    ⚠️  Rate limited! Waiting 2s...")
                time.sleep(2)
                self.stats["errors"] += 1
            else:
                self.stats["errors"] += 1
        except requests.exceptions.ConnectionError:
            print(f"    ❌ Connection failed — is the backend running on {self.api_url}?")
            self.stats["errors"] += 1

    def run_attack(self, attack: dict):
        """Run a single attack scenario."""
        attack_type = attack.get("type", "burst")
        name = attack.get("name", "Unknown Attack")

        print(f"\n  🎯 {name}")

        if attack_type == "burst":
            self._run_burst(attack)
        elif attack_type == "slow_rate":
            self._run_slow_rate(attack)
        elif attack_type == "ato":
            self._run_ato(attack)
        elif attack_type == "ip_rotation":
            self._run_ip_rotation(attack)
        elif attack_type == "distributed":
            self._run_distributed(attack)
        elif attack_type == "mixed":
            self._run_mixed(attack)
        else:
            print(f"    ⚠️  Unknown attack type: {attack_type}")

    def _run_burst(self, attack: dict):
        """Rapid burst of requests from same IP."""
        count = attack.get("count", 5)
        interval = attack.get("interval", 0.05)

        for i in range(count):
            payload = {
                "event_type": attack["event_type"],
                "source_ip": attack["source_ip"],
                "status": attack["status"],
                "endpoint": attack.get("endpoint_pattern", attack.get("endpoint", "")).replace("{i}", str(i)),
                "method": attack.get("method", "POST"),
            }
            if "user_id" in attack:
                payload["user_id"] = attack["user_id"]
            elif "user_id_pattern" in attack:
                payload["user_id"] = attack["user_id_pattern"].replace("{i}", str(i))
            if "device_id" in attack:
                payload["device_id"] = attack["device_id"]
            if "user_agent" in attack:
                ua = random.choice(USER_AGENTS) if attack.get("rotate_user_agent") else attack["user_agent"]
                payload["user_agent"] = ua
            if "headers" in attack:
                payload["headers"] = attack["headers"]

            self.send_log(payload)
            time.sleep(interval)

        print(f"    ✅ Sent {count} requests")

    def _run_slow_rate(self, attack: dict):
        """Slow-rate attack with long delays between requests."""
        count = attack.get("count", 8)
        interval = attack.get("interval", 2.0)

        print(f"    ⏱  Slow-rate: {interval}s between attempts ({count} total, ~{count * interval:.0f}s)")
        for i in range(count):
            payload = {
                "event_type": attack["event_type"],
                "source_ip": attack["source_ip"],
                "status": attack["status"],
                "endpoint": attack.get("endpoint", "/api/v1/auth/login"),
                "method": attack.get("method", "POST"),
            }
            if "user_id_pattern" in attack:
                payload["user_id"] = attack["user_id_pattern"].replace("{i}", str(i))
            if attack.get("rotate_user_agent"):
                payload["user_agent"] = random.choice(USER_AGENTS)
            else:
                payload["user_agent"] = attack.get("user_agent", "Mozilla/5.0")

            self.send_log(payload)
            if i < count - 1:
                time.sleep(interval)

        print(f"    ✅ Sent {count} slow-rate requests")

    def _run_ato(self, attack: dict):
        """Account takeover pattern: N failed logins then 1 success."""
        failed_count = attack.get("failed_count", 4)
        target_user = attack["target_user"]

        for i in range(failed_count):
            self.send_log({
                "event_type": "login",
                "source_ip": attack["source_ip"],
                "user_id": target_user,
                "status": "failed",
                "device_id": attack.get("device_id", "new-device"),
                "user_agent": attack.get("user_agent", "Mozilla/5.0"),
                "endpoint": attack.get("endpoint", "/api/v1/auth/login"),
                "method": "POST",
            })
            time.sleep(0.05)

        # Successful login
        self.send_log({
            "event_type": "login",
            "source_ip": attack["source_ip"],
            "user_id": target_user,
            "status": "success",
            "device_id": attack.get("device_id", "new-device"),
            "user_agent": attack.get("user_agent", "Mozilla/5.0"),
            "endpoint": attack.get("endpoint", "/api/v1/auth/login"),
            "method": "POST",
        })

        print(f"    ✅ Sent {failed_count} failed + 1 success (ATO pattern for {target_user})")

    def _run_ip_rotation(self, attack: dict):
        """Same device/fingerprint across multiple IPs."""
        count = attack.get("count", 5)
        ip_range = attack.get("ip_range", [1, count + 1])
        ip_pattern = attack.get("ip_pattern", "192.168.2.{ip}")

        for i in range(ip_range[0], ip_range[1]):
            ip = ip_pattern.replace("{ip}", str(i))
            payload = {
                "event_type": attack["event_type"],
                "source_ip": ip,
                "status": attack["status"],
                "endpoint": attack.get("endpoint", "/api/v1/auth/login"),
                "method": attack.get("method", "POST"),
            }
            if "user_id" in attack:
                payload["user_id"] = attack["user_id"]
            if "device_id" in attack:
                payload["device_id"] = attack["device_id"]
            if "user_agent" in attack:
                payload["user_agent"] = attack["user_agent"]
            if "headers" in attack:
                payload["headers"] = attack["headers"]

            self.send_log(payload)
            time.sleep(attack.get("interval", 0.1))

        count_sent = ip_range[1] - ip_range[0]
        print(f"    ✅ Sent {count_sent} requests from {count_sent} different IPs")

    def _run_distributed(self, attack: dict):
        """Botnet-style distributed attack from many IPs targeting same user."""
        target_user = attack["target_user"]
        ip_count = attack.get("ip_count", 10)
        attempts_per_ip = attack.get("attempts_per_ip", 2)

        for ip_idx in range(ip_count):
            ip = f"10.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            for attempt in range(attempts_per_ip):
                self.send_log({
                    "event_type": attack.get("event_type", "login"),
                    "source_ip": ip,
                    "user_id": target_user,
                    "status": attack.get("status", "failed"),
                    "device_id": f"botnet-node-{ip_idx}",
                    "user_agent": random.choice(USER_AGENTS),
                    "endpoint": attack.get("endpoint", "/api/v1/auth/login"),
                    "method": attack.get("method", "POST"),
                })
                time.sleep(attack.get("interval", 0.05))

        total = ip_count * attempts_per_ip
        print(f"    ✅ Sent {total} requests from {ip_count} IPs targeting {target_user}")

    def _run_mixed(self, attack: dict):
        """Interleaved legitimate + malicious traffic."""
        total = attack.get("total_requests", 50)
        ratio = attack.get("malicious_ratio", 0.1)
        legit_patterns = attack.get("legitimate_patterns", [])
        malicious_patterns = attack.get("malicious_patterns", [])

        malicious_count = int(total * ratio)
        legit_count = total - malicious_count

        # Build shuffled request queue
        queue = []
        for _ in range(legit_count):
            pattern = random.choice(legit_patterns)
            queue.append({
                "event_type": pattern["event_type"],
                "source_ip": random.choice(LEGIT_IPS),
                "user_id": random.choice(LEGIT_USERS),
                "status": pattern["status"],
                "user_agent": random.choice(LEGIT_USER_AGENTS),
                "endpoint": pattern["endpoint"],
                "method": "POST" if pattern["event_type"] in ("login", "order") else "GET",
                "_type": "legit",
            })

        for _ in range(malicious_count):
            pattern = random.choice(malicious_patterns)
            queue.append({
                "event_type": pattern["event_type"],
                "source_ip": pattern.get("source_ip", f"192.168.99.{random.randint(1, 255)}"),
                "status": pattern.get("status", "failed"),
                "user_agent": random.choice(USER_AGENTS),
                "endpoint": pattern["endpoint"],
                "method": "POST",
                "_type": "malicious",
            })

        random.shuffle(queue)

        actual_legit = 0
        actual_malicious = 0
        for req in queue:
            req_type = req.pop("_type", "legit")
            if req_type == "malicious":
                actual_malicious += 1
            else:
                actual_legit += 1
            self.send_log(req)
            time.sleep(random.uniform(0.01, 0.1))

        print(f"    ✅ Sent {total} requests ({actual_legit} legit, {actual_malicious} malicious)")


# ══════════════════════════════════════════════════════════════
#  CLI ENTRY POINT
# ══════════════════════════════════════════════════════════════

def main():
    scenario_name = "default"

    if "--list" in sys.argv:
        print("\n📋 Available Scenarios:\n")
        for key, scenario in SCENARIOS.items():
            print(f"  {key:15s} — {scenario['description']}")
        print(f"\n  {'all':15s} — Run all scenarios sequentially")
        print(f"\nUsage: python simulate_attacks.py --scenario <name>")
        return

    if "--scenario" in sys.argv:
        idx = sys.argv.index("--scenario")
        if idx + 1 < len(sys.argv):
            scenario_name = sys.argv[idx + 1]

    print("=" * 60)
    print("  🛡️  AI SOC — ATTACK SIMULATION SUITE")
    print("=" * 60)

    simulator = AttackSimulator()

    if scenario_name == "all":
        for name, scenario in SCENARIOS.items():
            print(f"\n{'━' * 60}")
            print(f"  📦 Scenario: {scenario['name']}")
            print(f"  📝 {scenario['description']}")
            print(f"{'━' * 60}")
            for attack in scenario["attacks"]:
                simulator.run_attack(attack)
            time.sleep(1)
    elif scenario_name in SCENARIOS:
        scenario = SCENARIOS[scenario_name]
        print(f"\n  📦 Scenario: {scenario['name']}")
        print(f"  📝 {scenario['description']}\n")
        for attack in scenario["attacks"]:
            simulator.run_attack(attack)
            time.sleep(0.5)
    else:
        print(f"\n  ❌ Unknown scenario: {scenario_name}")
        print(f"  Run with --list to see available scenarios.")
        return

    print(f"\n{'=' * 60}")
    print(f"  ✅ SIMULATION COMPLETE")
    print(f"  📊 Sent: {simulator.stats['sent']} | Errors: {simulator.stats['errors']}")
    print(f"  🖥️  Check the dashboard at http://127.0.0.1:8000")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
