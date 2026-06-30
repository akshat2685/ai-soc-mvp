import requests

def test_topology():
    # Login
    login_res = requests.post(
        "http://127.0.0.1:8000/auth/login",
        json={"username": "i.jain.akshat@gmail.com", "password": "Pass@1234"}
    )
    if login_res.status_code != 200:
        print("Login failed:", login_res.text)
        return
        
    token = login_res.json()["token"]
    print("Login successful! Token retrieved.")
    
    # Get Topology
    top_res = requests.get(
        "http://127.0.0.1:8000/api/v1/digital_twin/topology",
        headers={"Authorization": f"Bearer {token}"}
    )
    print("Topology Status:", top_res.status_code)
    if top_res.status_code == 200:
        print("Topology Payload:")
        print(top_res.json())
    else:
        print("Topology Error:", top_res.text)

if __name__ == "__main__":
    test_topology()
