"""
backend/threat_intel/lexical_url.py
Lexical URL Analysis — detects phishing/malicious URLs
purely from URL structure. Zero API, fully offline.
"""
import re
from urllib.parse import urlparse, parse_qs

# Suspicious keywords commonly found in phishing URLs
PHISHING_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "secure",
    "account", "update", "confirm", "banking", "paypal", "apple",
    "microsoft", "google", "amazon", "netflix", "ebay", "wallet",
    "password", "credential", "authenticate", "validation", "recover",
    "unlock", "suspended", "limited", "unusual", "alert", "notice"
]

MALWARE_KEYWORDS = [
    "download", "install", "setup", "crack", "keygen", "patch",
    "free", "torrent", "warez", "nulled", "hack", "cheat", "loader"
]

# Trusted domains that should never be flagged
WHITELIST = {
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "facebook.com", "twitter.com", "github.com", "wikipedia.org",
    "youtube.com", "linkedin.com", "instagram.com", "netflix.com"
}

# TLDs commonly abused in phishing
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click",
    ".link", ".online", ".site", ".web", ".live", ".stream", ".loan",
    ".work", ".date", ".faith", ".racing", ".win", ".download"
}


def analyze_url_lexical(url: str) -> dict:
    """
    Analyze URL structure for phishing/malware indicators.
    Returns risk score, threat type, and list of flags.
    """
    if not url:
        return {"engine": "Lexical Analysis", "status": "unavailable"}

    # Normalize
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path   = parsed.path.lower()
        query  = parsed.query.lower()
        full   = url.lower()
    except Exception as e:
        return {"engine": "Lexical Analysis", "status": "error", "error": str(e)}

    # Strip port from domain
    domain_clean = domain.split(":")[0]

    # Check whitelist
    for w in WHITELIST:
        if domain_clean == w or domain_clean.endswith("." + w):
            return {
                "engine":    "Lexical Analysis",
                "status":    "clean",
                "verdict":   "Clean",
                "score":     0,
                "flags":     [],
                "threat_type": "None",
                "risk_level": "Low"
            }

    flags      = []
    score      = 0
    threat_type = "Unknown"

    # ── 1. IP address used instead of domain ──────────────────────────────
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain_clean):
        flags.append("IP address used as domain (common in malware C2)")
        score += 30
        threat_type = "Malware/C2"

    # ── 2. Excessive subdomains ───────────────────────────────────────────
    subdomain_count = domain_clean.count(".")
    if subdomain_count >= 4:
        flags.append(f"Excessive subdomains ({subdomain_count}) — phishing technique")
        score += 20
        threat_type = "Phishing"

    # ── 3. Suspicious TLD ─────────────────────────────────────────────────
    for tld in SUSPICIOUS_TLDS:
        if domain_clean.endswith(tld):
            flags.append(f"Suspicious TLD '{tld}' — commonly abused in phishing")
            score += 15
            if threat_type == "Unknown":
                threat_type = "Phishing"
            break

    # ── 4. Phishing keywords in domain ───────────────────────────────────
    matched_phish = [kw for kw in PHISHING_KEYWORDS if kw in domain_clean]
    if matched_phish:
        flags.append(f"Phishing keywords in domain: {', '.join(matched_phish[:3])}")
        score += 15 * min(len(matched_phish), 3)
        threat_type = "Phishing"

    # ── 5. Phishing keywords in path/query ───────────────────────────────
    matched_path = [kw for kw in PHISHING_KEYWORDS if kw in path or kw in query]
    if matched_path:
        flags.append(f"Phishing keywords in URL path: {', '.join(matched_path[:3])}")
        score += 10 * min(len(matched_path), 2)
        if threat_type == "Unknown":
            threat_type = "Phishing"

    # ── 6. Malware keywords ───────────────────────────────────────────────
    matched_malware = [kw for kw in MALWARE_KEYWORDS if kw in full]
    if matched_malware:
        flags.append(f"Malware distribution keywords: {', '.join(matched_malware[:3])}")
        score += 20
        threat_type = "Malware Distribution"

    # ── 7. Brand impersonation (domain ≠ brand) ──────────────────────────
    brands = {
        "paypal": "paypal.com", "apple": "apple.com",
        "microsoft": "microsoft.com", "amazon": "amazon.com",
        "google": "google.com", "netflix": "netflix.com",
        "facebook": "facebook.com", "instagram": "instagram.com",
        "ebay": "ebay.com", "bank": None
    }
    for brand, legit in brands.items():
        if brand in domain_clean:
            if legit and not domain_clean.endswith(legit):
                flags.append(f"Brand impersonation: '{brand}' in domain but not on official site")
                score += 40
                threat_type = "Phishing — Brand Impersonation"
                break

    # ── 8. Homograph / lookalike characters ──────────────────────────────
    lookalikes = {"0": "o", "1": "l", "rn": "m", "vv": "w"}
    for fake, real in lookalikes.items():
        if fake in domain_clean:
            flags.append(f"Possible homograph attack: '{fake}' may impersonate '{real}'")
            score += 15
            if threat_type == "Unknown":
                threat_type = "Phishing — Homograph Attack"
            break

    # ── 9. URL length ─────────────────────────────────────────────────────
    if len(url) > 200:
        flags.append(f"Abnormally long URL ({len(url)} chars) — obfuscation technique")
        score += 10

    # ── 10. Excessive special characters ─────────────────────────────────
    special_count = url.count("-") + url.count("_") + url.count("%") + url.count("@")
    if special_count > 8:
        flags.append(f"Excessive special characters ({special_count}) — obfuscation")
        score += 10

    # ── 11. @ symbol in URL (credential theft trick) ─────────────────────
    if "@" in parsed.netloc:
        flags.append("@ symbol in URL — used to disguise destination domain")
        score += 35
        threat_type = "Phishing — Credential Theft"

    # ── 12. Multiple redirects encoded in URL ────────────────────────────
    redirect_params = ["redirect", "url=", "goto=", "return=", "next=", "redir="]
    for rp in redirect_params:
        if rp in query:
            flags.append(f"Open redirect parameter detected: '{rp}'")
            score += 15
            break

    # ── 13. Executable file extensions ───────────────────────────────────
    exe_exts = [".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi", ".scr"]
    for ext in exe_exts:
        if path.endswith(ext):
            flags.append(f"URL serves executable file: '{ext}'")
            score += 25
            threat_type = "Malware Distribution"
            break

    # ── 14. HTTP (not HTTPS) for sensitive operations ────────────────────
    if url.startswith("http://") and any(kw in full for kw in ["login", "signin", "account", "banking"]):
        flags.append("Non-HTTPS connection for sensitive operation — credential theft risk")
        score += 20
        if threat_type == "Unknown":
            threat_type = "Phishing"

    # Clamp score
    score = min(score, 100)

    # Verdict
    if score >= 60:    verdict = "Malicious"
    elif score >= 30:  verdict = "Suspicious"
    else:              verdict = "Clean"

    risk_map = {"Malicious": "Critical", "Suspicious": "High", "Clean": "Low"}

    return {
        "engine":      "Lexical Analysis",
        "status":      "found" if score > 0 else "clean",
        "verdict":     verdict,
        "score":       score,
        "threat_type": threat_type if score > 0 else "None",
        "flags":       flags,
        "risk_level":  risk_map[verdict],
        "checks_run":  14,
    }