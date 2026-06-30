import sys
import os
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend"))

from database import get_db
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def update_admin():
    password_hash = pwd_context.hash("admin")
    with get_db() as conn:
        conn.execute("UPDATE users SET password_hash = ? WHERE username = 'admin'", (password_hash,))
        conn.commit()
        print("Admin user password updated successfully.")

if __name__ == "__main__":
    update_admin()
