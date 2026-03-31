"""
backend/threat_intel/whois_lookup.py
WHOIS lookup using free whois.arin.net / RDAP APIs
No API key required
"""
import json, urllib.request, urllib.error, re
from datetime import datetime, timezone


def _rdap_lookup(domain: str) -> dict:
    """Use RDAP (modern WHOIS replacement) - completely free."""
    try:
        req = urllib.request.Request(
            f"https://rdap.org/domain/{domain}",
            headers={"Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        return {"error": str(e)}


def _parse_date(date_str: str):
    """Parse various date formats."""
    if not date_str:
        return None
    try:
        date_str = date_str.replace("Z", "+00:00")
        return datetime.fromisoformat(date_str)
    except:
        try:
            return datetime.strptime(date_str[:10], "%Y-%m-%d")
        except:
            return None


def lookup_whois(domain: str) -> dict:
    """Look up WHOIS/RDAP info for a domain."""
    if not domain:
        return {"engine": "WHOIS", "status": "unavailable", "error": "No domain"}

    # Strip port if present
    domain = domain.split(":")[0]
    # Skip IPs
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
        return _ip_whois(domain)

    data = _rdap_lookup(domain)
    if "error" in data:
        return {"engine": "WHOIS", "status": "unavailable", "error": data["error"]}

    try:
        # Extract dates
        created = None
        expires = None
        updated = None
        for event in (data.get("events") or []):
            action = event.get("eventAction", "")
            dt = _parse_date(event.get("eventDate", ""))
            if action == "registration":   created = dt
            elif action == "expiration":   expires = dt
            elif action == "last changed": updated = dt

        # Registrar
        registrar = ""
        for entity in (data.get("entities") or []):
            roles = entity.get("roles") or []
            if "registrar" in roles:
                vcard = entity.get("vcardArray") or []
                if len(vcard) > 1:
                    for item in vcard[1]:
                        if isinstance(item, list) and item[0] == "fn":
                            registrar = item[3]
                            break

        # Nameservers
        nameservers = []
        for ns in (data.get("nameservers") or [])[:4]:
            nsname = ns.get("ldhName") or ""
            if nsname:
                nameservers.append(nsname.lower())

        # Status
        statuses = data.get("status") or []

        # Age calculation
        now = datetime.now(timezone.utc)
        domain_age_days = None
        newly_registered = False
        if created:
            try:
                c = created.replace(tzinfo=timezone.utc) if created.tzinfo is None else created
                domain_age_days = (now - c).days
                newly_registered = domain_age_days < 90
            except:
                pass

        # Privacy protection detection
        privacy_protected = any(
            kw in str(data).lower()
            for kw in ["privacy", "redacted", "withheld", "protected", "whoisguard"]
        )

        return {
            "engine":           "WHOIS",
            "status":           "found",
            "domain":           domain,
            "registrar":        registrar or "Unknown",
            "created":          created.strftime("%Y-%m-%d") if created else "",
            "expires":          expires.strftime("%Y-%m-%d") if expires else "",
            "updated":          updated.strftime("%Y-%m-%d") if updated else "",
            "domain_age_days":  domain_age_days,
            "newly_registered": newly_registered,
            "privacy_protected": privacy_protected,
            "nameservers":      nameservers,
            "statuses":         statuses[:4],
        }
    except Exception as e:
        return {"engine": "WHOIS", "status": "parse_error", "error": str(e)}


def _ip_whois(ip: str) -> dict:
    """RDAP lookup for IP addresses via ARIN."""
    try:
        req = urllib.request.Request(
            f"https://rdap.arin.net/registry/ip/{ip}",
            headers={"Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode())

        name   = data.get("name") or ""
        handle = data.get("handle") or ""
        country = ""
        org = ""
        for entity in (data.get("entities") or []):
            roles = entity.get("roles") or []
            if "registrant" in roles:
                vcard = entity.get("vcardArray") or []
                if len(vcard) > 1:
                    for item in vcard[1]:
                        if isinstance(item, list):
                            if item[0] == "adr" and isinstance(item[3], dict):
                                country = item[3].get("country-name", "")
                            if item[0] == "org":
                                org = item[3]

        return {
            "engine":  "WHOIS",
            "status":  "found",
            "domain":  ip,
            "type":    "IP",
            "name":    name,
            "handle":  handle,
            "org":     org,
            "country": country,
            "newly_registered": False,
            "privacy_protected": False,
        }
    except Exception as e:
        return {"engine": "WHOIS", "status": "unavailable", "error": str(e)}
