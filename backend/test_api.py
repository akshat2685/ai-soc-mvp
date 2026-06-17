import httpx
import json

def test_apis():
    print("Logging in...")
    login_res = httpx.post("http://127.0.0.1:8000/auth/login", json={"username": "admin", "password": "admin"})
    token = login_res.json().get("token")
    headers = {"Authorization": f"Bearer {token}"}
    
    print("Testing Executive Dashboard Metrics...")
    try:
        res = httpx.get("http://127.0.0.1:8000/api/v1/executive/metrics", headers=headers, timeout=30.0)
        print("Executive Metrics Response:")
        print(json.dumps(res.json(), indent=2))
    except Exception as e:
        print(f"Executive Metrics failed: {e}")
        
    print("\nTesting Multi-Agent Orchestration...")
    try:
        res = httpx.post(
            "http://127.0.0.1:8000/api/v1/agents/task",
            json={"task": "Investigate the recent Botnet C2 alerts and provide a summary."},
            headers=headers,
            timeout=120.0
        )
        print("Agent Task Response:")
        print(json.dumps(res.json(), indent=2))
    except Exception as e:
        print(f"Agent Task failed: {e}")

if __name__ == "__main__":
    test_apis()
