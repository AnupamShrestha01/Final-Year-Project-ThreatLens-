"""
backend/threat_intel/metadefender.py
MetaDefender Cloud — multi-AV hash lookup.
Requires METADEFENDER_API_KEY in .env
"""
import os
import requests
from dotenv import load_dotenv

load_dotenv()

MD_API_KEY = os.getenv("METADEFENDER_API_KEY", "")


def scan_hash_metadefender(hash_value: str) -> dict:
    """
    Look up a hash against MetaDefender's multi-AV engine database.
    Returns malicious/clean counts, per-vendor results, and file metadata.
    """
    if not MD_API_KEY:
        return {
            "engine": "MetaDefender",
            "status": "error",
            "error":  "METADEFENDER_API_KEY not set in .env"
        }

    hash_value = hash_value.strip().lower()

    try:
        url     = f"https://api.metadefender.com/v4/hash/{hash_value}"
        headers = {"apikey": MD_API_KEY}
        r = requests.get(url, headers=headers, timeout=15)

        if r.status_code == 404:
            return {
                "engine":  "MetaDefender",
                "status":  "not_found",
                "message": "Hash not found in MetaDefender database"
            }

        if r.status_code == 401:
            return {
                "engine": "MetaDefender",
                "status": "error",
                "error":  "Invalid or expired API key"
            }

        if r.status_code == 429:
            return {
                "engine": "MetaDefender",
                "status": "error",
                "error":  "Rate limit exceeded — try again later"
            }

        if r.status_code != 200:
            return {
                "engine": "MetaDefender",
                "status": "error",
                "error":  f"HTTP {r.status_code}"
            }

        data         = r.json()
        scan_results = data.get("scan_results", {})
        engine_map   = scan_results.get("scan_details", {})

        malicious = 0
        clean     = 0
        vendors   = []

        for engine_name, details in engine_map.items():
            threat          = details.get("threat_found", "") or ""
            scan_result_i   = details.get("scan_result_i", 0)

            # scan_result_i: 0 = clean, 1 = infected, 2 = suspicious, 10 = not_found
            if scan_result_i == 1:
                malicious += 1
                vendors.append({
                    "engine":  engine_name,
                    "verdict": "malicious",
                    "threat":  threat
                })
            elif scan_result_i == 2:
                vendors.append({
                    "engine":  engine_name,
                    "verdict": "suspicious",
                    "threat":  threat
                })
            elif scan_result_i == 0:
                clean += 1
                vendors.append({
                    "engine":  engine_name,
                    "verdict": "clean",
                    "threat":  ""
                })
            else:
                vendors.append({
                    "engine":  engine_name,
                    "verdict": "unknown",
                    "threat":  threat
                })

        file_info   = data.get("file_info", {})
        total       = len(vendors)

        return {
            "engine":        "MetaDefender",
            "status":        "found",
            "malicious":     malicious,
            "clean":         clean,
            "total_engines": total,
            "threat_name":   scan_results.get("scan_all_result_a", ""),
            "file_name":     file_info.get("display_name", ""),
            "file_size":     file_info.get("file_size", ""),
            "file_type":     file_info.get("file_type_description", ""),
            "md5":           file_info.get("md5", ""),
            "sha1":          file_info.get("sha1", ""),
            "sha256":        file_info.get("sha256", ""),
            "vendors":       vendors
        }

    except requests.exceptions.Timeout:
        return {"engine": "MetaDefender", "status": "error", "error": "Request timed out"}
    except requests.exceptions.ConnectionError:
        return {"engine": "MetaDefender", "status": "error", "error": "Connection failed"}
    except Exception as e:
        return {"engine": "MetaDefender", "status": "error", "error": str(e)}