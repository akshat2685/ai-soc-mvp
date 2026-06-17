import sys
import os
sys.path.append(os.getcwd())
from database import get_db

def check_db():
    with get_db() as conn:
        logs = conn.execute("SELECT COUNT(*) as c FROM logs").fetchone()['c']
        alerts = conn.execute("SELECT COUNT(*) as c FROM alerts").fetchone()['c']
        incidents = conn.execute("SELECT COUNT(*) as c FROM incidents").fetchone()['c']
        responses = conn.execute("SELECT COUNT(*) as c FROM responses").fetchone()['c']
        
        print(f"Total Logs: {logs}")
        print(f"Total Alerts: {alerts}")
        print(f"Total Incidents: {incidents}")
        print(f"Total Responses: {responses}")
        
        cur = conn.execute("SELECT attack_type, COUNT(*) as c FROM alerts GROUP BY attack_type")
        print("Alerts by Type:")
        for row in cur:
            print(f"  {row['attack_type']}: {row['c']}")

if __name__ == "__main__":
    check_db()
