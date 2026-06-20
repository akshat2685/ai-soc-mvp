import sys
from integrations.virustotal import VirusTotalClient
from testing.shadow_mode import ShadowModePipeline
import asyncio
from api.emergency import trigger_panic_button

def mock_detection_rule(payload):
    if "admin" in payload.get("user", ""):
        return {"detected": True, "reason": "Admin access detected"}
    return {"detected": False}

async def test_quick_wins():
    print("--- Testing VirusTotal Enrichment ---")
    vt = VirusTotalClient()
    rep = vt.get_ip_reputation("10.0.0.1")
    print(f"Internal IP Reputation: {rep}")
    rep_ext = vt.get_ip_reputation("8.8.8.8")
    print(f"External IP Reputation: {rep_ext}")
    
    print("\n--- Testing Shadow Mode ---")
    shadow = ShadowModePipeline()
    shadow.execute_in_shadow("experimental_admin_check", mock_detection_rule, {"user": "admin_test"})
    print(f"Shadow Metrics: {shadow.get_shadow_metrics()}")
    
    print("\n--- Testing Panic Button ---")
    panic_res = await trigger_panic_button()
    print(f"Panic Output: {panic_res}")
    
if __name__ == "__main__":
    asyncio.run(test_quick_wins())
