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

async def sync_cve_feed() -> dict:
    """
    Synchronizes the general CVE feed (simulated for MVP).
    In a production system, this would pull from CIRCL API or NVD data feeds.
    """
    print("[THREAT INTEL] Synchronizing general CVE feed (simulated mode)")
    
    # We use a simulated seed list to avoid massive NVD downloads for MVP
    simulated_cves = [
        {"cve_id": "CVE-2023-44487", "description": "The HTTP/2 protocol allows a denial of service.", "cvss_score": 7.5, "severity": "HIGH", "published_date": "2023-10-10", "last_modified_date": "2023-10-20"},
        {"cve_id": "CVE-2023-38545", "description": "A flaw in curl could allow an attacker to trigger a heap-based buffer overflow.", "cvss_score": 9.8, "severity": "CRITICAL", "published_date": "2023-10-18", "last_modified_date": "2023-10-25"},
        {"cve_id": "CVE-2024-21626", "description": "A vulnerability in runc allowing container breakout.", "cvss_score": 8.6, "severity": "HIGH", "published_date": "2024-01-31", "last_modified_date": "2024-02-05"}
    ]
    
    inserted_count = 0
    try:
        with get_db() as conn:
            for cve in simulated_cves:
                conn.execute(
                    "INSERT OR REPLACE INTO cve_feed ("
                    "    cve_id, description, cvss_score, severity, published_date, last_modified_date"
                    ") VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        cve["cve_id"],
                        cve["description"],
                        cve["cvss_score"],
                        cve["severity"],
                        cve["published_date"],
                        cve["last_modified_date"]
                    )
                )
                inserted_count += 1
            conn.commit()
            
        print(f"[THREAT INTEL] Successfully synchronized {inserted_count} CVEs to cve_feed table.")
        return {"status": "success", "synced_records": inserted_count}
    except Exception as e:
        err_msg = f"Failed to sync CVE feed: {str(e)}"
        print(f"[THREAT INTEL] {err_msg}")
        return {"status": "error", "message": err_msg}

async def sync_cvelist_v5() -> dict:
    """
    Synchronizes vulnerability data from the CVEProject/cvelistV5 repository.
    Streams recent CVE JSON files directly into memory to avoid downloading the entire repo.
    """
    print("[THREAT INTEL] Synchronizing recent CVEs from CVEProject/cvelistV5...")
    
    # We will fetch a subset of recent CVEs for the MVP to save time/bandwidth
    # E.g., CVE-2024-xxxx
    url = "https://api.github.com/repos/CVEProject/cvelistV5/contents/cves/2024/10"
    
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code != 200:
            return {"status": "error", "message": "Failed to fetch CVE list from GitHub"}
            
        files = resp.json()
        inserted_count = 0
        
        with get_db() as conn:
            # We will just parse the first 20 recent CVEs for the MVP demonstration
            for file_info in files[:20]:
                if file_info['name'].endswith('.json'):
                    raw_url = file_info['download_url']
                    cve_resp = requests.get(raw_url, timeout=5)
                    if cve_resp.status_code == 200:
                        cve_data = cve_resp.json()
                        cve_id = cve_data.get("cveMetadata", {}).get("cveId")
                        containers = cve_data.get("containers", {}).get("cna", {})
                        
                        # Extract description
                        desc_list = containers.get("descriptions", [])
                        description = desc_list[0].get("value", "") if desc_list else ""
                        
                        # Extract severity/cvss if available
                        metrics = containers.get("metrics", [])
                        cvss_score = 0.0
                        severity = "UNKNOWN"
                        
                        for m in metrics:
                            if "cvssV3_1" in m:
                                cvss_score = m["cvssV3_1"].get("baseScore", 0.0)
                                severity = m["cvssV3_1"].get("baseSeverity", "UNKNOWN").upper()
                                break
                            elif "cvssV3_0" in m:
                                cvss_score = m["cvssV3_0"].get("baseScore", 0.0)
                                severity = m["cvssV3_0"].get("baseSeverity", "UNKNOWN").upper()
                                break
                                
                        published = cve_data.get("cveMetadata", {}).get("datePublished", "")
                        modified = cve_data.get("cveMetadata", {}).get("dateUpdated", "")
                        
                        if cve_id:
                            conn.execute(
                                "INSERT OR REPLACE INTO cve_feed ("
                                "    cve_id, description, cvss_score, severity, published_date, last_modified_date"
                                ") VALUES (?, ?, ?, ?, ?, ?)",
                                (cve_id, description, cvss_score, severity, published, modified)
                            )
                            inserted_count += 1
            conn.commit()
            
        print(f"[THREAT INTEL] Successfully synchronized {inserted_count} CVEs from CVEListV5.")
        return {"status": "success", "synced_records": inserted_count}
    except Exception as e:
        err_msg = f"Failed to sync CVEListV5: {str(e)}"
        print(f"[THREAT INTEL] {err_msg}")
        return {"status": "error", "message": err_msg}

def check_cve(cve_id: str) -> dict:
    """
    Retrieves general CVE metadata from the cve_feed table.
    """
    if not cve_id:
        return None
        
    with get_db() as conn:
        cur = conn.execute(
            "SELECT cve_id, description, cvss_score, severity, published_date, last_modified_date "
            "FROM cve_feed WHERE cve_id = ?",
            (cve_id,)
        )
        row = cur.fetchone()
        if row:
            return dict(row)
            
    # Fallback to CIRCL API if not in database
    try:
        resp = requests.get(f"https://cve.circl.lu/api/cve/{cve_id}", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            if data:
                return {
                    "cve_id": data.get("id"),
                    "description": data.get("summary"),
                    "cvss_score": data.get("cvss"),
                    "severity": "CRITICAL" if data.get("cvss", 0) >= 9.0 else ("HIGH" if data.get("cvss", 0) >= 7.0 else "MEDIUM"),
                    "published_date": data.get("Published"),
                    "last_modified_date": data.get("Modified")
                }
    except Exception as e:
        print(f"[THREAT INTEL] CIRCL API fallback failed for {cve_id}: {e}")
        
    return None

def check_file_hash(hash_value: str) -> dict:
    """
    Queries the MalwareBazaar API to check if a file hash is malicious.
    Uses the provided API key.
    """
    import os
    from dotenv import load_dotenv
    load_dotenv()
    
    # User's provided MalwareBazaar API Key
    api_key = os.environ.get("MALWARE_BAZAAR_API_KEY", "2662d74646f9c7662234c0943ddba477b78f147372682c63")
    
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {
        'query': 'get_info',
        'hash': hash_value
    }
    headers = {
        'API-KEY': api_key
    }
    
    try:
        response = requests.post(url, data=data, headers=headers, timeout=5)
        if response.status_code == 200:
            result = response.json()
            if result.get('query_status') == 'ok' and result.get('data'):
                # It's known malware
                malware_data = result['data'][0]
                return {
                    "is_malicious": True,
                    "signature": malware_data.get("signature", "Unknown"),
                    "tags": malware_data.get("tags", []),
                    "file_name": malware_data.get("file_name"),
                    "file_type": malware_data.get("file_type_mime"),
                    "first_seen": malware_data.get("first_seen")
                }
            elif result.get('query_status') == 'hash_not_found':
                return {"is_malicious": False, "message": "Hash not found in MalwareBazaar"}
    except Exception as e:
        print(f"[THREAT INTEL] MalwareBazaar query failed for {hash_value}: {e}")
        
    return None
