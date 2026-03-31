"""
backend/threat_intel/dns_intel.py
DNS Intelligence using dnspython — direct DNS queries, no API needed.

Install: pip install dnspython

Checks:
  - A records (IPv4)
  - AAAA records (IPv6)
  - MX records (mail servers)
  - NS records (nameservers)
  - TXT records (SPF, DMARC, DKIM)
  - CNAME records
  - Fast-flux detection (multiple IPs = botnet indicator)
  - Missing SPF/DMARC (phishing indicator)
  - Suspicious nameserver patterns
"""
import socket
import re

# ── Try dnspython ─────────────────────────────────────────────────────────
try:
    import dns.resolver
    import dns.exception
    DNS_LIB = True
except ImportError:
    DNS_LIB = False


# ── Fallback: socket-based basic DNS ─────────────────────────────────────
def _basic_dns(domain: str) -> dict:
    """Minimal DNS using stdlib socket — works without dnspython."""
    result = {
        "engine":  "DNS Intelligence",
        "status":  "partial",
        "source":  "stdlib socket (install dnspython for full analysis)",
        "domain":  domain,
        "a_records": [],
        "flags":   [],
    }
    try:
        infos = socket.getaddrinfo(domain, None)
        ips = list(set(i[4][0] for i in infos))
        result["a_records"] = ips[:8]
        if len(ips) >= 4:
            result["flags"].append("Multiple IPs detected — possible fast-flux")
        result["ip_count"] = len(ips)
    except Exception as e:
        result["status"] = "unavailable"
        result["error"]  = str(e)
    return result


# ── Known suspicious nameserver providers ────────────────────────────────
SUSPICIOUS_NS = [
    "topdns", "njalla", "1984hosting", "hostinger", "namecheap",
    "privacyguardian", "withheldforprivacy",
]

FREE_DYNAMIC_DNS = [
    "duckdns", "no-ip", "noip", "ddns", "changeip", "afraid.org",
    "dyndns", "dynu", "freeddns", "hopto.org", "myftp.org",
]


# ── Helpers ───────────────────────────────────────────────────────────────
def _query(resolver, domain: str, rtype: str) -> list:
    try:
        answers = resolver.resolve(domain, rtype, lifetime=5)
        return [r.to_text() for r in answers]
    except (dns.exception.DNSException, Exception):
        return []


def _parse_spf(txt_records: list) -> dict:
    for txt in txt_records:
        if "v=spf1" in txt.lower():
            hard_fail = "-all" in txt
            soft_fail = "~all" in txt
            return {
                "exists":     True,
                "record":     txt.strip('"'),
                "hard_fail":  hard_fail,
                "soft_fail":  soft_fail,
                "secure":     hard_fail,
            }
    return {"exists": False}


def _parse_dmarc(txt_records: list, domain: str, resolver) -> dict:
    # Check _dmarc subdomain
    dmarc_records = _query(resolver, f"_dmarc.{domain}", "TXT")
    for txt in dmarc_records:
        if "v=dmarc1" in txt.lower():
            policy = "none"
            m = re.search(r'p=(\w+)', txt, re.IGNORECASE)
            if m: policy = m.group(1).lower()
            return {
                "exists":  True,
                "record":  txt.strip('"'),
                "policy":  policy,
                "secure":  policy in ("quarantine", "reject"),
            }
    return {"exists": False}


# ── Main engine ───────────────────────────────────────────────────────────
def get_dns_intel(domain: str) -> dict:
    """
    Full DNS intelligence for a domain.
    Uses dnspython if available, falls back to stdlib.
    """
    if not domain:
        return {"engine": "DNS Intelligence", "status": "unavailable", "error": "No domain"}

    domain = domain.split(":")[0].strip().lower()

    # Skip raw IPs
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
        return {
            "engine":  "DNS Intelligence",
            "status":  "not_applicable",
            "note":    "DNS intelligence not applicable for raw IP addresses",
        }

    if not DNS_LIB:
        return _basic_dns(domain)

    resolver = dns.resolver.Resolver()
    resolver.timeout  = 5
    resolver.lifetime = 8

    # ── Query all record types ────────────────────────────────────────────
    a_records    = _query(resolver, domain, "A")
    aaaa_records = _query(resolver, domain, "AAAA")
    mx_records   = _query(resolver, domain, "MX")
    ns_records   = _query(resolver, domain, "NS")
    txt_records  = _query(resolver, domain, "TXT")
    cname_records= _query(resolver, domain, "CNAME")

    if not a_records and not ns_records:
        return {
            "engine": "DNS Intelligence",
            "status": "not_found",
            "domain": domain,
            "verdict": "Clean",
        }

    # ── SPF / DMARC ───────────────────────────────────────────────────────
    spf   = _parse_spf(txt_records)
    dmarc = _parse_dmarc(txt_records, domain, resolver)

    # ── MX parsing ───────────────────────────────────────────────────────
    mail_servers = []
    for mx in mx_records[:5]:
        parts = mx.split()
        if len(parts) >= 2:
            mail_servers.append({"priority": parts[0], "host": parts[1].rstrip(".")})

    # ── NS parsing ────────────────────────────────────────────────────────
    nameservers = [ns.rstrip(".").lower() for ns in ns_records[:6]]

    # ── TXT records (strip quotes) ────────────────────────────────────────
    txt_clean = [t.strip('"') for t in txt_records[:8]]

    # ── Risk scoring & flags ──────────────────────────────────────────────
    flags      = []
    risk_score = 0

    # Fast-flux: many A records = botnet rotation
    ip_count = len(a_records)
    if ip_count >= 8:
        risk_score += 40
        flags.append(f"Fast-flux detected — {ip_count} IP addresses (botnet indicator)")
    elif ip_count >= 4:
        risk_score += 20
        flags.append(f"Multiple A records ({ip_count} IPs) — possible fast-flux")

    # Missing SPF — phishing indicator
    if not spf["exists"]:
        risk_score += 15
        flags.append("No SPF record — domain may be used for email spoofing")
    elif not spf.get("secure"):
        risk_score += 8
        flags.append("SPF record uses soft-fail (~all) — not fully protected")

    # Missing DMARC — phishing indicator
    if not dmarc["exists"]:
        risk_score += 15
        flags.append("No DMARC record — no email authentication policy")
    elif dmarc.get("policy") == "none":
        risk_score += 8
        flags.append("DMARC policy is 'none' — monitoring only, not enforced")

    # Free dynamic DNS — common in malware C2
    domain_lower = domain.lower()
    for dyn in FREE_DYNAMIC_DNS:
        if dyn in domain_lower:
            risk_score += 30
            flags.append(f"Free dynamic DNS detected ({dyn}) — common in malware C2")
            break

    # Suspicious nameservers
    ns_str = " ".join(nameservers).lower()
    for sus in SUSPICIOUS_NS:
        if sus in ns_str:
            risk_score += 10
            flags.append(f"Potentially privacy-focused nameserver detected: {sus}")
            break

    # No MX records (domain not set up for email — unusual for legit business)
    if not mail_servers and not re.match(r'^(www\.|mail\.|ftp\.)', domain):
        flags.append("No MX records — domain not configured to receive email")

    # CNAME to suspicious domain
    for cn in cname_records:
        for dyn in FREE_DYNAMIC_DNS:
            if dyn in cn.lower():
                risk_score += 25
                flags.append(f"CNAME points to dynamic DNS: {cn}")

    risk_score = min(risk_score, 100)

    verdict = "Malicious"  if risk_score >= 60 \
         else "Suspicious" if risk_score >= 25 \
         else "Clean"

    return {
        "engine":        "DNS Intelligence",
        "status":        "found",
        "source":        "dnspython (direct DNS)",
        "domain":        domain,
        "verdict":       verdict,
        "risk_score":    risk_score,
        "flags":         flags,

        # Records
        "a_records":     a_records[:8],
        "aaaa_records":  aaaa_records[:4],
        "mx_records":    mail_servers,
        "ns_records":    nameservers,
        "txt_records":   txt_clean,
        "cname_records": [c.rstrip(".") for c in cname_records],

        # Email security
        "spf":           spf,
        "dmarc":         dmarc,

        # Stats
        "ip_count":      ip_count,
        "has_ipv6":      len(aaaa_records) > 0,
        "has_mail":      len(mail_servers) > 0,
        "fast_flux":     ip_count >= 4,
    }