import sys
import os
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend"))

from database import get_db
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def create_admin():
    password_hash = pwd_context.hash("admin")
    with get_db() as conn:
        try:
            conn.execute("INSERT INTO users (username, password_hash, role, tenant_id) VALUES (?, ?, ?, ?)", 
                         ("admin", password_hash, "ADMIN", "default"))
            conn.commit()
            print("Admin user created successfully.")
        except Exception as e:
            print("Admin user already exists or error:", e)

if __name__ == "__main__":
    create_admin()
