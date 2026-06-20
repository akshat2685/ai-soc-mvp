import os
import random
import uuid
import datetime
import sqlite3
import psycopg2
from faker import Faker

fake = Faker()

DB_TYPE = os.environ.get("DB_TYPE", "sqlite")
POSTGRES_HOST = os.environ.get("POSTGRES_HOST", "localhost")
POSTGRES_PORT = int(os.environ.get("POSTGRES_PORT", 5432))
POSTGRES_DB = os.environ.get("POSTGRES_DB", "soc")
POSTGRES_USER = os.environ.get("POSTGRES_USER", "soc")
POSTGRES_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "changeme")

def get_connection():
    if DB_TYPE == "postgres":
        return psycopg2.connect(
            host=POSTGRES_HOST,
            port=POSTGRES_PORT,
            database=POSTGRES_DB,
            user=POSTGRES_USER,
            password=POSTGRES_PASSWORD
        )
    else:
        db_path = os.path.join(os.path.dirname(__file__), "soc.db")
        return sqlite3.connect(db_path)

def generate_assets(num_assets=50):
    print(f"Generating {num_assets} enterprise assets...")
    assets = []
    departments = ["Engineering", "HR", "Sales", "Finance", "IT", "Executive"]
    os_types = ["Windows Server 2022", "Ubuntu 22.04", "Red Hat Enterprise Linux 9", "Windows 11", "macOS Sonoma"]
    criticality_levels = ["Low", "Medium", "High", "Critical"]

    for _ in range(num_assets):
        asset_id = f"ast-{uuid.uuid4().hex[:8]}"
        hostname = fake.hostname()
        ip = fake.ipv4_private()
        os_ver = random.choice(os_types)
        criticality = random.choice(criticality_levels)
        owner = fake.name()
        dept = random.choice(departments)
        assets.append((asset_id, hostname, ip, os_ver, criticality, owner, dept))
    
    conn = get_connection()
    cursor = conn.cursor()
    
    query = "INSERT INTO assets (asset_id, hostname, ip, os, criticality, owner, dept) VALUES (%s, %s, %s, %s, %s, %s, %s)" if DB_TYPE == "postgres" else "INSERT INTO assets (asset_id, hostname, ip, os, criticality, owner, dept) VALUES (?, ?, ?, ?, ?, ?, ?)"
    
    # SQLite fallback syntax
    if DB_TYPE != "postgres":
        query = query.replace("%s", "?")

    for asset in assets:
        try:
            cursor.execute(query, asset)
        except Exception as e:
            print(f"Error inserting asset {asset[0]}: {e}")
            conn.rollback()
            continue
    conn.commit()
    cursor.close()
    conn.close()
    print("Assets successfully generated and saved to memory layer.")

def generate_users(num_users=100):
    print(f"Generating {num_users} enterprise users...")
    users = []
    departments = ["Engineering", "HR", "Sales", "Finance", "IT", "Executive"]
    risk_profiles = ["Low", "Low", "Low", "Medium", "High"] # Weighted random
    
    for _ in range(num_users):
        user_id = fake.user_name()
        usual_country = fake.country()
        usual_login_time = f"{random.randint(7,10):02d}:00"
        risk_profile = random.choice(risk_profiles)
        timestamp = datetime.datetime.now().isoformat()
        users.append((user_id, usual_country, usual_login_time, risk_profile, timestamp))
    
    conn = get_connection()
    cursor = conn.cursor()
    
    query = "INSERT INTO user_memory (user_id, usual_country, usual_login_time, risk_profile, timestamp) VALUES (%s, %s, %s, %s, %s)" if DB_TYPE == "postgres" else "INSERT INTO user_memory (user_id, usual_country, usual_login_time, risk_profile, timestamp) VALUES (?, ?, ?, ?, ?)"
    
    for user in users:
        try:
            cursor.execute(query, user)
        except Exception as e:
            print(f"Error inserting user {user[0]}: {e}")
            conn.rollback()
            continue
    conn.commit()
    cursor.close()
    conn.close()
    print("Users successfully baselined into user memory.")

if __name__ == "__main__":
    generate_assets(20)
    generate_users(50)
