import requests
import time

API_URL = "http://127.0.0.1:8000/ingest"

print("=" * 60)
print("  AI SOC — ATTACK SIMULATION SUITE")
print("=" * 60)

# ── 1. Credential Stuffing ──
bad_ip_1 = "192.168.1.100"
print(f"\n[1/5] Simulating CREDENTIAL STUFFING from {bad_ip_1}...")
for i in range(6):
    requests.post(API_URL, json={
        "event_type": "login",
        "source_ip": bad_ip_1,
        "user_id": f"admin{i}",
        "status": "failed",
        "device_id": "unknown-device",
        "user_agent": "Mozilla/5.0",
        "endpoint": "/api/v1/auth/login",
        "method": "POST"
    })
    time.sleep(0.05)
print(f"    ✅ Sent 6 failed login attempts")

time.sleep(0.5)

# ── 2. OTP / SMS Pumping ──
bad_ip_2 = "203.0.113.45"
print(f"\n[2/5] Simulating OTP PUMPING from {bad_ip_2}...")
for i in range(4):
    requests.post(API_URL, json={
        "event_type": "otp_request",
        "source_ip": bad_ip_2,
        "status": "success",
        "device_id": "bot-net-2",
        "user_agent": "Mozilla/5.0",
        "endpoint": "/api/v1/auth/otp/send",
        "method": "POST"
    })
    time.sleep(0.05)
print(f"    ✅ Sent 4 OTP requests")

time.sleep(0.5)

# ── 3. Bot Scraping ──
bad_ip_3 = "10.0.0.77"
print(f"\n[3/5] Simulating BOT SCRAPING from {bad_ip_3}...")
for i in range(12):
    requests.post(API_URL, json={
        "event_type": "page_view",
        "source_ip": bad_ip_3,
        "status": "success",
        "user_agent": "python-requests/2.28.0",
        "endpoint": f"/api/v1/products/{i}",
        "method": "GET"
    })
    time.sleep(0.02)
print(f"    ✅ Sent 12 bot requests with suspicious user-agent")

time.sleep(0.5)

# ── 4. Account Takeover ──
bad_ip_4 = "172.16.0.55"
target_user = "victim_user_42"
print(f"\n[4/5] Simulating ACCOUNT TAKEOVER from {bad_ip_4} targeting {target_user}...")
for i in range(4):
    requests.post(API_URL, json={
        "event_type": "login",
        "source_ip": bad_ip_4,
        "user_id": target_user,
        "status": "failed",
        "device_id": "new-device-xyz",
        "user_agent": "Mozilla/5.0 Chrome/120",
        "endpoint": "/api/v1/auth/login",
        "method": "POST"
    })
    time.sleep(0.05)

# Successful login after failed attempts = ATO
requests.post(API_URL, json={
    "event_type": "login",
    "source_ip": bad_ip_4,
    "user_id": target_user,
    "status": "success",
    "device_id": "new-device-xyz",
    "user_agent": "Mozilla/5.0 Chrome/120",
    "endpoint": "/api/v1/auth/login",
    "method": "POST"
})
print(f"    ✅ Sent 4 failed + 1 successful login (ATO pattern)")

time.sleep(0.5)

# ── 5. Business Logic / Coupon Abuse ──
bad_ip_5 = "198.51.100.22"
abuser_user = "coupon_abuser_99"
print(f"\n[5/5] Simulating COUPON ABUSE from {bad_ip_5} by {abuser_user}...")
for i in range(4):
    requests.post(API_URL, json={
        "event_type": "coupon_apply",
        "source_ip": bad_ip_5,
        "user_id": abuser_user,
        "status": "success",
        "user_agent": "Mozilla/5.0",
        "endpoint": "/api/v1/checkout/coupon",
        "method": "POST"
    })
    time.sleep(0.05)
print(f"    ✅ Sent 4 coupon applications from same user")

print("\n" + "=" * 60)
print("  SIMULATION COMPLETE — Check the dashboard!")
print("=" * 60)
