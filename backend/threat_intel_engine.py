import requests
import json
from database import get_db

CISA_KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

async def sync_cisa_kev() -> dict:
    """
    Fetches the latest CISA Known Exploited Vulnerabilities (KEV) catalog and stores/updates it in the SQLite database.
    """
    print(f"[THREAT INTEL] Synchronizing CISA KEV list from {CISA_KEV_FEED_URL}")
    try:
        # Fetch the feed
        resp = requests.get(CISA_KEV_FEED_URL, timeout=10)
        if resp.status_code != 200:
            return {"status": "error", "message": f"Feed returned status code {resp.status_code}"}
            
        data = resp.json()
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return {"status": "error", "message": "No vulnerabilities key found in feed."}
            
        # Bulk insert/update in database
        inserted_count = 0
        with get_db() as conn:
            for vuln in vulnerabilities:
                cve_id = vuln.get("cveID")
                if not cve_id:
                    continue
                
                conn.execute(
                    "INSERT OR REPLACE INTO cisa_kev ("
                    "    cve_id, vendor_project, product, vulnerability_name, "
                    "    date_added, short_description, required_action"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        cve_id,
                        vuln.get("vendorProject"),
                        vuln.get("product"),
                        vuln.get("vulnerabilityName"),
                        vuln.get("dateAdded"),
                        vuln.get("shortDescription"),
                        vuln.get("requiredAction")
                    )
                )
                inserted_count += 1
            conn.commit()
            
        print(f"[THREAT INTEL] Successfully synchronized {inserted_count} CVEs to cisa_kev table.")
        return {"status": "success", "synced_records": inserted_count}
        
    except Exception as e:
        err_msg = f"Failed to sync with CISA KEV feed: {str(e)}"
        print(f"[THREAT INTEL] {err_msg} - Using existing cached/seeded KEV list.")
        return {"status": "error", "message": err_msg}

def check_cve_kev(cve_id: str) -> dict:
    """
    Checks if a given CVE ID is listed in the CISA KEV database.
    Returns metadata if found, otherwise None.
    """
    if not cve_id:
        return None
        
    with get_db() as conn:
        cur = conn.execute(
            "SELECT cve_id, vendor_project, product, vulnerability_name, date_added, short_description, required_action "
            "FROM cisa_kev WHERE cve_id = ?",
            (cve_id,)
        )
        row = cur.fetchone()
        if row:
            return dict(row)
    return None
