import sqlite3
conn = sqlite3.connect('backend/soc.db')
cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = [r[0] for r in cur.fetchall()]
print("Tables:", tables)
print("Has simulations:", "simulations" in tables)
print("Has evaluations:", "evaluations" in tables)
conn.close()
