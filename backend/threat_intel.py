import os
import json
import time
from database import get_db

ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY")

# Hardcoded geo data for common private/test IPs used in simulations
_SIMULATED_GEO = {
    "192.168.1.100": {"country": "Russia", "countryCode": "RU", "isp": "Dark Proxy Network", "abuseScore": 95, "usageType": "Data Center/Proxy"},
    "203.0.113.45": {"country": "Nigeria", "countryCode": "NG", "isp": "SMS Gateway Abuse LLC", "abuseScore": 88, "usageType": "Commercial"},
    "10.0.0.77": {"country": "China", "countryCode": "CN", "isp": "Bot Farm Hosting Co.", "abuseScore": 72, "usageType": "Data Center"},
    "172.16.0.55": {"country": "Brazil", "countryCode": "BR", "isp": "Compromised VPS Provider", "abuseScore": 81, "usageType": "Data Center/VPN"},
    "198.51.100.22": {"country": "United States", "countryCode": "US", "isp": "Residential ISP", "abuseScore": 35, "usageType": "Residential"},
}

_COUNTRY_FLAGS = {
    "RU": "🇷🇺", "NG": "🇳🇬", "CN": "🇨🇳", "BR": "🇧🇷", "US": "🇺🇸",
    "IN": "🇮🇳", "DE": "🇩🇪", "GB": "🇬🇧", "FR": "🇫🇷", "JP": "🇯🇵",
    "KR": "🇰🇷", "IR": "🇮🇷", "UA": "🇺🇦", "NL": "🇳🇱", "AU": "🇦🇺",
}

def enrich_ip(ip: str) -> dict:
    """Enrich an IP with threat intelligence. Uses AbuseIPDB if key is set, else simulated data."""

    # Check cache first
    with get_db() as conn:
        cur = conn.execute("SELECT * FROM threat_intel WHERE ip = ?", (ip,))
        cached = cur.fetchone()
        if cached:
            return dict(cached)

    # Try real AbuseIPDB
    if ABUSEIPDB_API_KEY:
        result = _query_abuseipdb(ip)
        if result:
            _cache_result(ip, result)
            return result

    # Fallback to simulated data
    sim = _SIMULATED_GEO.get(ip, {
        "country": "Unknown",
        "countryCode": "??",
        "isp": "Unknown ISP",
        "abuseScore": 50,
        "usageType": "Unknown"
    })
    result = {
        "ip": ip,
        "country": sim["country"],
        "country_code": sim["countryCode"],
        "flag": _COUNTRY_FLAGS.get(sim["countryCode"], "🏳️"),
        "isp": sim["isp"],
        "abuse_score": sim["abuseScore"],
        "usage_type": sim["usageType"],
        "source": "simulated",
    }
    _cache_result(ip, result)
    return result


def _query_abuseipdb(ip: str) -> dict:
    try:
        import requests
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        resp = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params, timeout=5)
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            cc = data.get("countryCode", "??")
            return {
                "ip": ip,
                "country": data.get("countryName", "Unknown"),
                "country_code": cc,
                "flag": _COUNTRY_FLAGS.get(cc, "🏳️"),
                "isp": data.get("isp", "Unknown"),
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "usage_type": data.get("usageType", "Unknown"),
                "source": "abuseipdb",
            }
    except Exception as e:
        print(f"[THREAT INTEL] AbuseIPDB query failed for {ip}: {e}")
    return None


def _cache_result(ip: str, result: dict):
    with get_db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO threat_intel (ip, country, country_code, flag, isp, abuse_score, usage_type, source) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (ip, result["country"], result["country_code"], result.get("flag", ""), result["isp"], result["abuse_score"], result["usage_type"], result.get("source", "unknown"))
        )
        conn.commit()
