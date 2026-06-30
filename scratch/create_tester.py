import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))
import bcrypt
from database import get_db

username = "edysor_tester@test.com"
password = "Pass@1234"
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

with get_db() as conn:
    conn.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.execute(
        "INSERT INTO users (username, password_hash, role, tenant_id, is_active) VALUES (?, ?, ?, ?, 1)",
        (username, password_hash, "admin", "default")
    )
    conn.commit()
    print(f"User '{username}' created with password '{password}'")
    print(f"Hash: {password_hash[:30]}...")

    # Verify it's there
    cur = conn.execute("SELECT username, role, is_active FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    print(f"Verify: {dict(row)}")
