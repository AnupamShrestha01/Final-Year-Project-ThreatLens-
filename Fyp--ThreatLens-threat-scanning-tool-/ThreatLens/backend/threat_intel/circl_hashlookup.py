"""
backend/threat_intel/circl_hashlookup.py
CIRCL hashlookup — known-good file database (NSRL + trusted sources).
No API key required.
"""
import requests


def scan_hash_circl(hash_value: str) -> dict:
    """
    Check if a hash belongs to a known-good legitimate file.
    Trust score 0-100:  >50 = known good,  <50 = less trusted / unknown.
    404 = not in known-good DB (could be malware or simply unknown).
    """
    hash_value = hash_value.strip().lower()
    length = len(hash_value)

    if length == 32:
        hash_type = "md5"
    elif length == 40:
        hash_type = "sha1"
    elif length == 64:
        hash_type = "sha256"
    else:
        return {
            "engine": "CIRCL hashlookup",
            "status": "error",
            "error":  "Invalid hash length — expected 32 (MD5), 40 (SHA1), or 64 (SHA256) hex chars"
        }

    try:
        url = f"https://hashlookup.circl.lu/lookup/{hash_type}/{hash_value}"
        r = requests.get(url, timeout=10)

        if r.status_code == 404:
            return {
                "engine":     "CIRCL hashlookup",
                "status":     "not_found",
                "known_good": False,
                "message":    "Not found in CIRCL known-good database — unknown or potentially malicious file"
            }

        if r.status_code != 200:
            return {
                "engine": "CIRCL hashlookup",
                "status": "error",
                "error":  f"HTTP {r.status_code}"
            }

        data = r.json()
        trust_score = int(data.get("hashlookup:trust", 0))

        return {
            "engine":          "CIRCL hashlookup",
            "status":          "found",
            "known_good":      True,
            "trust_score":     trust_score,
            "file_name":       data.get("FileName", ""),
            "file_size":       data.get("FileSize", ""),
            "product_name":    data.get("ProductName", ""),
            "product_version": data.get("ProductVersion", ""),
            "publisher":       data.get("SpecialCode", ""),
            "os":              data.get("OpSystemCode", ""),
            "source":          data.get("source", "NSRL")
        }

    except requests.exceptions.Timeout:
        return {"engine": "CIRCL hashlookup", "status": "error", "error": "Request timed out"}
    except requests.exceptions.ConnectionError:
        return {"engine": "CIRCL hashlookup", "status": "error", "error": "Connection failed"}
    except Exception as e:
        return {"engine": "CIRCL hashlookup", "status": "error", "error": str(e)}