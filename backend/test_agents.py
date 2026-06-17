import requests

BASE_URL = "http://127.0.0.1:8000"

def test_multi_agent():
    print("Testing Multi-Agent Orchestration...")
    
    # 1. Login
    print("Logging in...")
    login_res = requests.post(f"{BASE_URL}/auth/login", json={"username": "admin", "password": "admin"})
    if login_res.status_code != 200:
        print(f"Login failed: {login_res.text}")
        return
        
    token = login_res.json().get("token")
    headers = {"Authorization": f"Bearer {token}"}
    print("Login successful.")
    
    # 2. Trigger Agent Team
    task = "Investigate the recent spike in failed logins from IP 192.168.1.50 and check if any CVEs apply to the targeted endpoints."
    print(f"Sending task: {task}")
    
    agent_res = requests.post(
        f"{BASE_URL}/api/v1/agents/task", 
        json={"task": task}, 
        headers=headers
    )
    
    if agent_res.status_code != 200:
        print(f"Agent Team failed: {agent_res.text}")
        return
        
    data = agent_res.json()
    print("Agent Team executed successfully!")
    print("\n--- Agent Messages ---")
    for msg in data.get("messages", []):
        print(msg)
        print("-" * 20)

if __name__ == "__main__":
    test_multi_agent()
