"""
backend/threat_intel/ssl_check.py
SSL Certificate Analysis — no API needed, pure Python ssl module.
Checks cert validity, age, issuer, and domain match.
"""
import ssl, socket, datetime, re


def check_ssl(domain: str) -> dict:
    """Analyze SSL certificate of a domain."""
    if not domain:
        return {"engine": "SSL Check", "status": "unavailable"}

    # Strip port and path
    domain = domain.split(":")[0].split("/")[0].strip()

    # Skip IPs
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
        return {
            "engine":  "SSL Check",
            "status":  "found",
            "verdict": "Suspicious",
            "flags":   ["IP address used — no SSL domain validation possible"],
            "score":   20,
            "has_ssl": False,
        }

    flags  = []
    score  = 0
    cert_info = {}

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        # ── Parse cert ──────────────────────────────────────────────────
        not_before_str = cert.get("notBefore", "")
        not_after_str  = cert.get("notAfter", "")
        issuer_raw     = dict(x[0] for x in cert.get("issuer", []))
        subject_raw    = dict(x[0] for x in cert.get("subject", []))
        san            = cert.get("subjectAltName", [])

        issuer_org  = issuer_raw.get("organizationName", "Unknown")
        issuer_cn   = issuer_raw.get("commonName", "")
        subject_cn  = subject_raw.get("commonName", "")

        # Parse dates
        fmt = "%b %d %H:%M:%S %Y %Z"
        now = datetime.datetime.utcnow()
        not_before = datetime.datetime.strptime(not_before_str, fmt) if not_before_str else None
        not_after  = datetime.datetime.strptime(not_after_str,  fmt) if not_after_str  else None

        # Cert age (how old is it)
        cert_age_days = (now - not_before).days if not_before else None
        days_left     = (not_after - now).days  if not_after  else None

        # ── Checks ──────────────────────────────────────────────────────

        # 1. Brand new cert (< 30 days) — phishing sites get new certs constantly
        if cert_age_days is not None and cert_age_days < 30:
            flags.append(f"Certificate only {cert_age_days} days old — newly issued certs common in phishing")
            score += 25

        # 2. Cert expiring very soon
        if days_left is not None and days_left < 10:
            flags.append(f"Certificate expires in {days_left} days")
            score += 10

        # 3. Self-signed (issuer == subject)
        if issuer_cn and subject_cn and issuer_cn == subject_cn:
            flags.append("Self-signed certificate — not trusted by browsers")
            score += 35

        # 4. Free CA — Let's Encrypt heavily abused by phishing sites
        if "Let's Encrypt" in issuer_org or "letsencrypt" in issuer_cn.lower():
            flags.append("Let's Encrypt certificate — free CA commonly used in phishing (not malicious alone)")
            score += 10

        # 5. Domain mismatch
        san_domains = [s[1] for s in san if s[0] == "DNS"]
        domain_matched = any(
            domain == s or domain.endswith("." + s.lstrip("*").lstrip("."))
            for s in san_domains
        )
        if not domain_matched and san_domains:
            flags.append(f"Domain mismatch — cert issued for {san_domains[0]} not {domain}")
            score += 40

        cert_info = {
            "issuer":        issuer_org,
            "issuer_cn":     issuer_cn,
            "subject":       subject_cn,
            "valid_from":    not_before.strftime("%Y-%m-%d") if not_before else "",
            "valid_to":      not_after.strftime("%Y-%m-%d")  if not_after  else "",
            "days_left":     days_left,
            "cert_age_days": cert_age_days,
            "san_domains":   san_domains[:4],
        }

    except ssl.SSLCertVerificationError as e:
        flags.append(f"SSL certificate verification failed: {str(e)[:80]}")
        score += 45
        cert_info = {"error": str(e)[:100]}
    except ssl.SSLError as e:
        flags.append(f"SSL error: {str(e)[:80]}")
        score += 30
        cert_info = {"error": str(e)[:100]}
    except ConnectionRefusedError:
        # No HTTPS at all
        flags.append("No HTTPS — site does not support SSL/TLS")
        score += 20
        cert_info = {"has_ssl": False}
    except Exception as e:
        return {"engine": "SSL Check", "status": "unavailable", "error": str(e)[:100]}

    score = min(score, 100)

    if score >= 50:    verdict = "Malicious"
    elif score >= 20:  verdict = "Suspicious"
    else:              verdict = "Clean"

    return {
        "engine":   "SSL Check",
        "status":   "found",
        "verdict":  verdict,
        "score":    score,
        "has_ssl":  "error" not in cert_info and "has_ssl" not in cert_info,
        "flags":    flags,
        "cert":     cert_info,
    }