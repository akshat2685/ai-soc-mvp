import sys
import os
import bcrypt

sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend"))
from database import get_db

def create_custom_user():
    username = "testuser@gmail.com"
    password = "Pass@1234"
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    
    with get_db() as conn:
        try:
            # Delete if exists
            conn.execute("DELETE FROM users WHERE username = ?", (username,))
            # Insert with proper role
            conn.execute(
                "INSERT INTO users (username, password_hash, role, tenant_id, is_active) VALUES (?, ?, ?, ?, 1)", 
                (username, password_hash, "admin", "default")
            )
            conn.commit()
            print(f"User '{username}' created/updated successfully with password '{password}' and role 'admin'.")
        except Exception as e:
            print("Error creating user:", e)

if __name__ == "__main__":
    create_custom_user()
