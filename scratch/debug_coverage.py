import sqlite3
conn = sqlite3.connect('backend/soc.db')
conn.row_factory = sqlite3.Row

# Check simulations schema
cur = conn.execute("PRAGMA table_info(simulations)")
print("simulations columns:", [r[1] for r in cur.fetchall()])

# Check evaluations schema
cur = conn.execute("PRAGMA table_info(evaluations)")
print("evaluations columns:", [r[1] for r in cur.fetchall()])

# Try the failing query
try:
    cur = conn.execute("SELECT COUNT(DISTINCT name) as c FROM simulations WHERE name LIKE 'Purple Team validation:%'")
    result = cur.fetchone()
    print("Query result type:", type(result))
    print("Query result:", dict(result) if result else None)
except Exception as e:
    print("Query failed:", e)

conn.close()
