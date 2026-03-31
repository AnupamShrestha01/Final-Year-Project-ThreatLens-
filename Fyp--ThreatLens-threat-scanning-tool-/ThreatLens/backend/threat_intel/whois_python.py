"""
backend/threat_intel/whois_python.py
WHOIS lookup using python-whois library (offline socket-based)
with fallback to RDAP API if library not installed.

Install: pip install python-whois
"""
import re
from datetime import datetime, timezone

# ── Try python-whois ──────────────────────────────────────────────────────
try:
    import whois as _whois
    WHOIS_LIB = True
except ImportError:
    WHOIS_LIB = False


# ── Fallback: existing RDAP ───────────────────────────────────────────────
def _rdap_fallback(domain: str) -> dict:
    try:
        from backend.threat_intel.whois_lookup import lookup_whois
        return lookup_whois(domain)
    except Exception as e:
        return {"engine": "WHOIS", "status": "unavailable", "error": str(e)}


def _to_str(val) -> str:
    """Safely convert whois date/list values to string."""
    if val is None:
        return ""
    if isinstance(val, list):
        val = val[0] if val else None
    if isinstance(val, datetime):
        return val.strftime("%Y-%m-%d")
    return str(val)[:10] if val else ""


def lookup_whois_python(domain: str) -> dict:
    """
    WHOIS lookup — uses python-whois (socket-based, offline capable)
    Falls back to RDAP API if library not installed.
    """
    if not domain:
        return {"engine": "WHOIS", "status": "unavailable", "error": "No domain"}

    domain = domain.split(":")[0].strip().lower()

    # Skip IPs — use RDAP for those
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
        return _rdap_fallback(domain)

    if not WHOIS_LIB:
        # Fallback to RDAP
        result = _rdap_fallback(domain)
        result["note"] = "python-whois not installed — using RDAP API. Run: pip install python-whois"
        return result

    try:
        w = _whois.whois(domain)

        if not w or not w.domain_name:
            return {"engine": "WHOIS", "status": "not_found",
                    "domain": domain, "verdict": "Clean"}

        # Dates
        created = w.creation_date
        expires = w.expiration_date
        updated = w.updated_date
        if isinstance(created, list): created = created[0]
        if isinstance(expires, list): expires = expires[0]
        if isinstance(updated, list): updated = updated[0]

        # Age
        now = datetime.now(timezone.utc)
        domain_age_days = None
        newly_registered = False
        if isinstance(created, datetime):
            try:
                c = created.replace(tzinfo=timezone.utc) if created.tzinfo is None else created
                domain_age_days = (now - c).days
                newly_registered = domain_age_days < 90
            except Exception:
                pass

        # Registrar
        registrar = w.registrar or "Unknown"
        if isinstance(registrar, list):
            registrar = registrar[0] if registrar else "Unknown"

        # Nameservers
        ns = w.name_servers or []
        if isinstance(ns, str): ns = [ns]
        nameservers = [n.lower() for n in list(ns)[:4] if n]

        # Emails / privacy
        emails = w.emails or []
        if isinstance(emails, str): emails = [emails]
        privacy_protected = any(
            kw in str(w).lower()
            for kw in ["privacy", "redacted", "withheld", "protected", "whoisguard", "domainprotect"]
        )

        # Registrant country
        country = getattr(w, "country", None) or ""
        if isinstance(country, list): country = country[0] if country else ""

        # Status
        status = w.status or []
        if isinstance(status, str): status = [status]
        statuses = [str(s).split(" ")[0] for s in status[:4]]

        return {
            "engine":            "WHOIS",
            "status":            "found",
            "source":            "python-whois (socket)",
            "domain":            domain,
            "registrar":         str(registrar),
            "created":           _to_str(created),
            "expires":           _to_str(expires),
            "updated":           _to_str(updated),
            "domain_age_days":   domain_age_days,
            "newly_registered":  newly_registered,
            "privacy_protected": privacy_protected,
            "nameservers":       nameservers,
            "country":           str(country),
            "statuses":          statuses,
        }

    except Exception as e:
        # If python-whois fails, fall back to RDAP
        result = _rdap_fallback(domain)
        result["whois_error"] = str(e)
        return result