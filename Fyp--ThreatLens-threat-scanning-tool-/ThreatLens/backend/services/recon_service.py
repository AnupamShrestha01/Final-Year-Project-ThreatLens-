"""
backend/services/recon_service.py
IP / Domain / URL Behavioral Recon Engine
Combines: port scan + banner grab + ASN + geolocation + DNS + WHOIS
Pure Python — no Docker needed.

Install: pip install ipwhois requests dnspython python-whois --break-system-packages
"""
import socket
import concurrent.futures
import json
import re
import requests
from datetime import datetime

# ── Top 20 ports to scan ──────────────────────────────────────────────────
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111,
    135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080
]

PORT_SERVICES = {
    21:   "FTP",        22:  "SSH",       23:  "Telnet",
    25:   "SMTP",       53:  "DNS",       80:  "HTTP",
    110:  "POP3",       111: "RPC",       135: "MSRPC",
    139:  "NetBIOS",    143: "IMAP",      443: "HTTPS",
    445:  "SMB",        993: "IMAPS",     995: "POP3S",
    1723: "PPTP VPN",   3306:"MySQL",     3389:"RDP",
    5900: "VNC",        8080:"HTTP-Alt"
}

SUSPICIOUS_PORTS = {
    23:   "Telnet open — unencrypted remote access",
    135:  "MSRPC open — common attack vector",
    139:  "NetBIOS open — SMB vulnerability risk",
    445:  "SMB open — EternalBlue/ransomware risk",
    1723: "PPTP VPN — weak encryption protocol",
    3389: "RDP open — brute force / ransomware risk",
    5900: "VNC open — remote desktop exposure",
    3306: "MySQL open — database exposed to internet",
}

HIGH_RISK_COUNTRIES = [
    "CN", "RU", "KP", "IR", "NG", "RO", "BR", "UA"
]


# ── Port scanner ──────────────────────────────────────────────────────────
def _scan_port(ip: str, port: int, timeout: float = 1.0) -> dict | None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        if result == 0:
            banner = ""
            try:
                sock.settimeout(2)
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                raw = sock.recv(256)
                banner = raw.decode("utf-8", errors="ignore").split("\r\n")[0][:100]
            except Exception:
                pass
            sock.close()
            return {
                "port":    port,
                "service": PORT_SERVICES.get(port, "Unknown"),
                "banner":  banner,
                "state":   "open"
            }
        sock.close()
        return None
    except Exception:
        return None


def _run_port_scan(ip: str) -> list:
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(_scan_port, ip, p): p for p in TOP_PORTS}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
    return sorted(open_ports, key=lambda x: x["port"])


# ── ASN + Geolocation ─────────────────────────────────────────────────────
def _get_ip_intel(ip: str) -> dict:
    intel = {
        "ip":          ip,
        "country":     "Unknown",
        "country_code": "",
        "city":        "Unknown",
        "org":         "Unknown",
        "asn":         "Unknown",
        "isp":         "Unknown",
        "is_vpn":      False,
        "is_tor":      False,
        "is_proxy":    False,
        "is_datacenter": False,
    }
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,org,as,isp,proxy,hosting",
            timeout=5
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                intel["country"]      = data.get("country", "Unknown")
                intel["country_code"] = data.get("countryCode", "")
                intel["city"]         = data.get("city", "Unknown")
                intel["org"]          = data.get("org", "Unknown")
                intel["asn"]          = data.get("as", "Unknown")
                intel["isp"]          = data.get("isp", "Unknown")
                intel["is_proxy"]     = data.get("proxy", False)
                intel["is_datacenter"]= data.get("hosting", False)
    except Exception:
        pass

    # Try ipwhois as backup for ASN
    if intel["asn"] == "Unknown":
        try:
            from ipwhois import IPWhois
            obj = IPWhois(ip)
            res = obj.lookup_rdap(depth=1)
            intel["asn"] = res.get("asn", "Unknown")
            intel["org"] = res.get("asn_description", "Unknown")
        except Exception:
            pass

    return intel


# ── Reverse DNS ───────────────────────────────────────────────────────────
def _reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


# ── Resolve domain to IP ──────────────────────────────────────────────────
def _resolve_domain(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except Exception:
        return ""


# ── Risk scoring ──────────────────────────────────────────────────────────
def _calculate_risk(open_ports, ip_intel, dns_data, whois_data, flags) -> tuple[int, str]:
    score = 0

    # Suspicious open ports
    for p in open_ports:
        if p["port"] in SUSPICIOUS_PORTS:
            score += 20

    # High risk country
    if ip_intel.get("country_code") in HIGH_RISK_COUNTRIES:
        score += 15
        flags.append(f"Hosted in high-risk country: {ip_intel.get('country')}")

    # Proxy / hosting / datacenter
    if ip_intel.get("is_proxy"):
        score += 20
        flags.append("IP flagged as proxy/VPN")
    if ip_intel.get("is_datacenter"):
        score += 10
        flags.append("Hosted on datacenter/cloud — common for C2 servers")

    # DNS flags
    if dns_data:
        score += min(dns_data.get("risk_score", 0) // 2, 30)
        flags.extend(dns_data.get("flags", []))

    # WHOIS flags
    if whois_data and whois_data.get("newly_registered"):
        score += 20
        flags.append("Domain registered less than 90 days ago — high phishing risk")
    if whois_data and whois_data.get("privacy_protected"):
        score += 5
        flags.append("WHOIS privacy protection enabled")

    score = min(score, 100)
    level = "HIGH" if score >= 70 else "MEDIUM" if score >= 40 else "LOW" if score >= 15 else "CLEAN"
    return score, level


# ── Main recon function ───────────────────────────────────────────────────
def run_recon(target: str) -> dict:
    """
    Full recon on IP, domain, or URL.
    Returns structured behavioral report.
    """
    start = datetime.now()

    # Clean target
    target = target.strip()
    target = re.sub(r'^https?://', '', target)
    target = target.split("/")[0].split("?")[0].strip()

    is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target))

    # Resolve to IP
    ip = target if is_ip else _resolve_domain(target)
    if not ip:
        return {
            "status":  "error",
            "error":   f"Could not resolve {target}",
            "target":  target,
            "threat_score": 0,
            "threat_level": "UNKNOWN"
        }

    flags = []
    open_ports = []
    dns_data   = {}
    whois_data = {}

    # ── Port scan ─────────────────────────────────────────────────────────
    open_ports = _run_port_scan(ip)

    # Flag suspicious ports
    for p in open_ports:
        if p["port"] in SUSPICIOUS_PORTS:
            flags.append(f"Port {p['port']} ({p['service']}) open — {SUSPICIOUS_PORTS[p['port']]}")

    # ── IP intelligence ───────────────────────────────────────────────────
    ip_intel = _get_ip_intel(ip)

    # ── Reverse DNS ───────────────────────────────────────────────────────
    rdns = _reverse_dns(ip) if is_ip else ""

    # ── DNS intelligence (domains only) ───────────────────────────────────
    if not is_ip:
        try:
            from backend.threat_intel.dns_intel import get_dns_intel
            dns_data = get_dns_intel(target)
        except Exception:
            pass

    # ── WHOIS (domains only) ──────────────────────────────────────────────
    if not is_ip:
        try:
            from backend.threat_intel.whois_python import lookup_whois_python
            whois_data = lookup_whois_python(target)
        except Exception:
            pass

    # ── Risk score ────────────────────────────────────────────────────────
    threat_score, threat_level = _calculate_risk(
        open_ports, ip_intel, dns_data, whois_data, flags
    )

    # ── MITRE tags ────────────────────────────────────────────────────────
    mitre_tags = []
    port_nums = [p["port"] for p in open_ports]
    if 3389 in port_nums: mitre_tags.append({"id": "T1021.001", "name": "Remote Desktop Protocol"})
    if 445  in port_nums: mitre_tags.append({"id": "T1021.002", "name": "SMB/Windows Admin Shares"})
    if 22   in port_nums: mitre_tags.append({"id": "T1021.004", "name": "SSH Remote Services"})
    if 5900 in port_nums: mitre_tags.append({"id": "T1021.005", "name": "VNC Remote Services"})
    if 3306 in port_nums: mitre_tags.append({"id": "T1190",     "name": "Exploit Public-Facing Application"})
    if ip_intel.get("is_proxy"):
        mitre_tags.append({"id": "T1090", "name": "Proxy"})
    if dns_data.get("fast_flux"):
        mitre_tags.append({"id": "T1568.001", "name": "Fast Flux DNS"})
    if whois_data.get("newly_registered"):
        mitre_tags.append({"id": "T1583.001", "name": "Acquire Infrastructure: Domains"})

    duration = (datetime.now() - start).seconds

    return {
        "status":        "completed",
        "target":        target,
        "resolved_ip":   ip,
        "reverse_dns":   rdns,
        "is_ip":         is_ip,
        "duration_seconds": duration,

        # Port scan
        "open_ports":    open_ports,
        "port_count":    len(open_ports),

        # IP intelligence
        "ip_intel":      ip_intel,

        # DNS + WHOIS (domains)
        "dns":           dns_data,
        "whois":         whois_data,

        # Risk
        "flags":         flags,
        "mitre_tags":    mitre_tags,
        "threat_score":  threat_score,
        "threat_level":  threat_level,
    }