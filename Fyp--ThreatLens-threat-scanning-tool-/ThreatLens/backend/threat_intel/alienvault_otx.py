"""
backend/threat_intel/alienvault_otx.py
AlienVault OTX — file hash lookup
"""
import os, json, urllib.request, urllib.error

OTX_BASE = "https://otx.alienvault.com/api/v1"

def _otx_get_key():
    return os.environ.get("OTX_API_KEY", "")

def _otx_get(endpoint):
    api_key = _otx_get_key()
    if not api_key:
        return {"error": "OTX_API_KEY not configured"}
    try:
        req = urllib.request.Request(
            OTX_BASE + endpoint,
            headers={"X-OTX-API-KEY": api_key, "Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}"}
    except Exception as e:
        return {"error": str(e)}

def lookup_file_hash(sha256):
    if not sha256:
        return {"engine": "AlienVault OTX", "status": "unavailable", "error": "No hash"}

    data = _otx_get(f"/indicators/file/{sha256}/general")
    if "error" in data:
        return {"engine": "AlienVault OTX", "status": "unavailable", "error": data["error"]}

    pulse_info  = data.get("pulse_info") or {}
    pulse_count = pulse_info.get("count", 0)
    pulses      = pulse_info.get("pulses") or []

    tags, adversaries, malware_families, threat_names = [], [], [], []
    for p in pulses[:10]:
        if not isinstance(p, dict): continue
        tags += p.get("tags") or []
        adv = p.get("adversary") or ""
        if adv: adversaries.append(adv)
        for mf in (p.get("malware_families") or []):
            if not isinstance(mf, dict): continue
            n = mf.get("display_name") or mf.get("id") or ""
            if n: malware_families.append(n)
        name = p.get("name") or ""
        if name: threat_names.append(name)

    tags             = list(set(tags))[:10]
    adversaries      = list(set(adversaries))[:5]
    malware_families = list(set(malware_families))[:5]
    threat_names     = threat_names[:5]

    verdict = "Clean"
    if pulse_count >= 5:   verdict = "Malicious"
    elif pulse_count >= 1: verdict = "Suspicious"

    return {
        "engine":           "AlienVault OTX",
        "status":           "found" if pulse_count > 0 else "clean",
        "verdict":          verdict,
        "pulse_count":      pulse_count,
        "threat_names":     threat_names,
        "tags":             tags,
        "adversaries":      adversaries,
        "malware_families": malware_families,
        "pulses": [
            {
                "name":    p.get("name") or "",
                "author":  p.get("author_name") or "",
                "created": (p.get("created") or "")[:10],
                "tags":    (p.get("tags") or [])[:5],
            }
            for p in pulses[:5] if isinstance(p, dict)
        ],
    }


def lookup_url_otx(domain: str, input_type: str = "domain") -> dict:
    """Look up URL/Domain/IP in AlienVault OTX."""
    if not domain:
        return {"engine": "AlienVault OTX", "status": "unavailable"}

    indicator_type = "IPv4" if input_type == "ip" else "domain"
    data = _otx_get(f"/indicators/{indicator_type}/{domain}/general")

    if "error" in data:
        return {"engine": "AlienVault OTX", "status": "unavailable", "error": data["error"]}

    pulse_info  = data.get("pulse_info") or {}
    pulse_count = pulse_info.get("count", 0)
    pulses      = pulse_info.get("pulses") or []

    tags, adversaries, malware_families = [], [], []
    for p in pulses[:10]:
        if not isinstance(p, dict): continue
        tags += p.get("tags") or []
        adv = p.get("adversary") or ""
        if adv: adversaries.append(adv)
        for mf in (p.get("malware_families") or []):
            if not isinstance(mf, dict): continue
            n = mf.get("display_name") or mf.get("id") or ""
            if n: malware_families.append(n)

    tags             = list(set(tags))[:8]
    adversaries      = list(set(adversaries))[:5]
    malware_families = list(set(malware_families))[:5]

    verdict = "Clean"
    if pulse_count >= 5:   verdict = "Malicious"
    elif pulse_count >= 1: verdict = "Suspicious"

    return {
        "engine":           "AlienVault OTX",
        "status":           "found" if pulse_count > 0 else "clean",
        "verdict":          verdict,
        "pulse_count":      pulse_count,
        "tags":             tags,
        "adversaries":      adversaries,
        "malware_families": malware_families,
        "pulses": [
            {
                "name":    p.get("name") or "",
                "author":  p.get("author_name") or "",
                "created": (p.get("created") or "")[:10],
                "tags":    (p.get("tags") or [])[:4],
            }
            for p in pulses[:5] if isinstance(p, dict)
        ],
    }
