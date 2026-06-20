import requests
import json
import csv
from io import StringIO
from datetime import datetime, timedelta
import asyncio
import os
import sys

# Add parent directory to path to allow importing from database.py
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database import get_db

URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
MALWARE_BAZAAR_CSV_URL = "https://bazaar.abuse.ch/export/csv/recent/"

import zipfile
import io

def fetch_urlhaus():
    """Fetches the last 30 days of malicious URLs from URLhaus."""
    print("[CTI AGENT] Fetching latest URLhaus payloads...")
    try:
        response = requests.get(URLHAUS_CSV_URL, timeout=15)
        if response.status_code != 200:
            print(f"[CTI AGENT] Failed to fetch URLhaus: {response.status_code}")
            return []
            
        csv_data = response.text
        # URLhaus CSVs start with comments starting with #
        lines = [line for line in csv_data.split('\n') if not line.startswith('#')]
        
        reader = csv.reader(lines)
        iocs = []
        for row in reader:
            if len(row) >= 3:
                # row[2] is the URL
                url = row[2].strip()
                if url:
                    iocs.append({
                        "ioc_value": url,
                        "ioc_type": "url",
                        "source": "URLhaus",
                        "threat_tags": "malware_download"
                    })
        return iocs
    except Exception as e:
        print(f"[CTI AGENT] URLhaus error: {e}")
        return []

def fetch_malware_bazaar():
    """Fetches the recent malware hashes from MalwareBazaar."""
    print("[CTI AGENT] Fetching latest MalwareBazaar hashes...")
    try:
        response = requests.get(MALWARE_BAZAAR_CSV_URL, timeout=20)
        if response.status_code != 200:
            print(f"[CTI AGENT] Failed to fetch MalwareBazaar: {response.status_code}")
            return []
            
        csv_data = response.text
        lines = [line for line in csv_data.split('\n') if not line.startswith('#')]
        
        reader = csv.reader(lines)
        iocs = []
        for row in reader:
            if len(row) >= 3:
                # row[1] is SHA256 hash, row[2] is MD5, row[5] is signature
                sha256 = row[1].strip()
                sig = row[5].strip() if len(row) > 5 else "unknown"
                if sha256:
                    iocs.append({
                        "ioc_value": sha256,
                        "ioc_type": "sha256",
                        "source": "MalwareBazaar",
                        "threat_tags": sig
                    })
        return iocs
    except Exception as e:
        print(f"[CTI AGENT] MalwareBazaar error: {e}")
        return []

def update_global_blacklist(iocs):
    """Inserts newly found IOCs into the database, ignoring duplicates."""
    if not iocs:
        return
        
    inserted = 0
    with get_db() as conn:
        for ioc in iocs:
            try:
                conn.execute(
                    "INSERT INTO global_ioc_feed (ioc_value, ioc_type, source, threat_tags) VALUES (?, ?, ?, ?)",
                    (ioc["ioc_value"], ioc["ioc_type"], ioc["source"], ioc["threat_tags"])
                )
                inserted += 1
            except Exception: # Usually sqlite3.IntegrityError for UNIQUE constraint
                pass
        conn.commit()
    print(f"[CTI AGENT] Successfully ingested {inserted} new IOCs into the Global Feed.")

async def run_daily_cti_ingestion():
    """Main orchestration function to run the CTI agent."""
    print(f"[CTI AGENT] Starting daily threat intelligence sync at {datetime.now().isoformat()}...")
    
    # 1. Fetch URLhaus
    urlhaus_iocs = fetch_urlhaus()
    # 2. Fetch MalwareBazaar
    bazaar_iocs = fetch_malware_bazaar()
    
    all_iocs = urlhaus_iocs + bazaar_iocs
    print(f"[CTI AGENT] Fetched a total of {len(all_iocs)} raw IOCs from open sources.")
    
    # 3. Update Database
    update_global_blacklist(all_iocs)
    print("[CTI AGENT] Daily sync complete. The SOC is now armed with the latest global threats.")

if __name__ == "__main__":
    asyncio.run(run_daily_cti_ingestion())
