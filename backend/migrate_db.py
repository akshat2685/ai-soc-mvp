import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "soc.db")

def migrate():
    conn = sqlite3.connect(DB_PATH)
    
    tables_to_add_tenant = ['logs', 'alerts', 'incidents', 'users', 'api_keys']
    
    for table in tables_to_add_tenant:
        try:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN tenant_id TEXT DEFAULT 'default'")
            print(f"Added tenant_id to {table}")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e).lower():
                print(f"Column tenant_id already exists in {table}")
            else:
                print(f"Error altering {table}: {e}")

    try:
        conn.execute("ALTER TABLE incidents ADD COLUMN analyst_notes TEXT")
        print("Added analyst_notes to incidents")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e).lower():
            print("Column analyst_notes already exists in incidents")
        else:
            print(f"Error altering incidents: {e}")
            
    conn.commit()
    conn.close()

if __name__ == "__main__":
    migrate()
