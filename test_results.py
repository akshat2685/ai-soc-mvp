import sqlite3
import pandas as pd

def main():
    print("=" * 60)
    print(" 🛡️  LIVE SYSTEM TEST RESULTS")
    print("=" * 60)

    conn = sqlite3.connect('backend/soc.db')
    
    # 1. Alerts Detected
    alerts_df = pd.read_sql_query("SELECT id, attack_type, severity, attacker_ip FROM alerts", conn)
    print("\n[1] ALERTS DETECTED")
    print("-" * 30)
    if not alerts_df.empty:
        print(f"Total Alerts: {len(alerts_df)}")
        print(alerts_df.groupby(['attack_type', 'severity']).size().reset_index(name='count').to_string(index=False))
    else:
        print("No alerts detected.")

    # 2. Correlated Incidents
    incidents_df = pd.read_sql_query("SELECT id, severity, status, correlation_key FROM incidents", conn)
    print("\n[2] CORRELATED INCIDENTS")
    print("-" * 30)
    if not incidents_df.empty:
        print(f"Total Incidents: {len(incidents_df)}")
        print(incidents_df.groupby(['severity', 'status']).size().reset_index(name='count').to_string(index=False))
    else:
        print("No incidents correlated.")

    # 3. Autonomous Responses Taken
    responses_df = pd.read_sql_query("SELECT action_type, response_tier, target, approval_status FROM responses", conn)
    print("\n[3] AUTONOMOUS RESPONSES TRIGGERED")
    print("-" * 30)
    if not responses_df.empty:
        print(f"Total Response Actions: {len(responses_df)}")
        print(responses_df.groupby(['action_type', 'response_tier', 'approval_status']).size().reset_index(name='count').to_string(index=False))
    else:
        print("No responses triggered.")

    # 4. Critical Actions Queued for Approval (Tier 4/5)
    approvals_df = pd.read_sql_query("SELECT action_type, target, status FROM approvals", conn)
    print("\n[4] PENDING APPROVALS (TIER 4/5 ACTIONS CATCHED)")
    print("-" * 30)
    if not approvals_df.empty:
        print(f"Actions safely queued instead of executing blindly: {len(approvals_df[approvals_df['status'] == 'PENDING'])}")
        print(approvals_df.groupby(['action_type', 'status']).size().reset_index(name='count').to_string(index=False))
    else:
        print("No approvals queued.")

    conn.close()

if __name__ == '__main__':
    main()
