import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))
from database import get_db

try:
    with get_db() as conn:
        cur = conn.execute("SELECT COUNT(DISTINCT name) as c FROM simulations WHERE name LIKE 'Purple Team validation:%'")
        result = cur.fetchone()
        print("Result:", result)
        if result:
            print("c:", result['c'])
except Exception as e:
    import traceback
    traceback.print_exc()
