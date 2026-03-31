"""
backend/threat_intel/google_safebrowsing.py
Google Safe Browsing API v4 — free, 10,000 req/day
Detects: phishing, malware, unwanted software, social engineering
"""
import os, json, urllib.request, urllib.error

GSB_API_KEY = os.environ.get("GOOGLE_SB_KEY", "")
GSB_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# Threat type → human readable category
THREAT_LABELS = {
    "MALWARE":             {"label": "Malware",              "icon": "🦠", "color": "#ff4444"},
    "SOCIAL_ENGINEERING":  {"label": "Phishing",             "icon": "🎣", "color": "#ff4444"},
    "UNWANTED_SOFTWARE":   {"label": "Unwanted Software",    "icon": "⚠️",  "color": "#ff8800"},
    "POTENTIALLY_HARMFUL_APPLICATION": {"label": "Harmful App", "icon": "💀", "color": "#ff4444"},
    "THREAT_TYPE_UNSPECIFIED": {"label": "Unknown Threat",   "icon": "⚠️",  "color": "#ff8800"},
}

PLATFORM_LABELS = {
    "ANY_PLATFORM":    "All Platforms",
    "WINDOWS":         "Windows",
    "LINUX":           "Linux",
    "ANDROID":         "Android",
    "OSX":             "macOS",
    "IOS":             "iOS",
    "CHROME":          "Chrome Browser",
}


def check_google_safebrowsing(url: str) -> dict:
    """Check URL against Google Safe Browsing database."""
    api_key = os.environ.get("GOOGLE_SB_KEY", GSB_API_KEY)
    if not api_key:
        return {"engine": "Google Safe Browsing", "status": "unavailable",
                "error": "No GOOGLE_SB_KEY in .env"}

    payload = {
        "client": {
            "clientId":      "threatlens",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes":     ["ANY_PLATFORM"],
            "threatEntryTypes":  ["URL"],
            "threatEntries":     [{"url": url}]
        }
    }

    try:
        req = urllib.request.Request(
            f"{GSB_URL}?key={api_key}",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            result = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            err = json.loads(e.read().decode())
            msg = err.get("error", {}).get("message", str(e))
        except:
            msg = str(e)
        return {"engine": "Google Safe Browsing", "status": "unavailable", "error": msg}
    except Exception as e:
        return {"engine": "Google Safe Browsing", "status": "unavailable", "error": str(e)}

    matches = result.get("matches", [])

    if not matches:
        return {
            "engine":      "Google Safe Browsing",
            "status":      "clean",
            "verdict":     "Clean",
            "threat_type": "None",
            "threat_label": "Not Listed",
            "matches":     [],
        }

    # Parse matches
    threats = []
    for m in matches:
        tt = m.get("threatType", "")
        pt = m.get("platformType", "")
        info = THREAT_LABELS.get(tt, {"label": tt, "icon": "⚠️", "color": "#ff8800"})
        threats.append({
            "threat_type":   tt,
            "threat_label":  info["label"],
            "threat_icon":   info["icon"],
            "threat_color":  info["color"],
            "platform":      PLATFORM_LABELS.get(pt, pt),
            "url":           m.get("threat", {}).get("url", url),
        })

    # Primary threat (most severe)
    primary = threats[0]
    severity_order = ["MALWARE", "POTENTIALLY_HARMFUL_APPLICATION", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"]
    for sev in severity_order:
        for t in threats:
            if t["threat_type"] == sev:
                primary = t
                break

    return {
        "engine":        "Google Safe Browsing",
        "status":        "found",
        "verdict":       "Malicious",
        "threat_type":   primary["threat_type"],
        "threat_label":  primary["threat_label"],
        "threat_icon":   primary["threat_icon"],
        "threat_color":  primary["threat_color"],
        "platform":      primary["platform"],
        "matches":       threats,
        "total_matches": len(threats),
    }