"""
backend/services/url_service.py

Professional URL / Domain / IP threat analysis — 7 engines:
  1. Local URLhaus DB         (offline blacklist)
  2. VirusTotal               (largest URL/AV coverage)
  3. URLScan.io               (live page analysis)
  4. AlienVault OTX           (threat intelligence pulses)
  5. WHOIS                    (domain registration context)
  6. DNS Intelligence         (infrastructure-level signals)
  7. Community Intel          (platform-wide social signal)
"""
import sys, os, re, socket, math
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))

from backend.threat_intel.virustotal      import scan_url_vt
from backend.threat_intel.urlscan         import scan_url_urlscan
from backend.threat_intel.whois_lookup    import lookup_whois
from backend.threat_intel.whois_python    import lookup_whois_python
from backend.threat_intel.alienvault_otx  import lookup_url_otx
from backend.threat_intel.url_db          import lookup_url_db
from backend.threat_intel.dns_intel       import get_dns_intel
from backend.threat_intel.community_intel import lookup_community_intel, update_community_intel


def _detect_input_type(value: str) -> str:
    value = value.strip()
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', value): return "ip"
    if value.startswith(("http://", "https://", "ftp://")): return "url"
    return "domain"


def _normalize_url(value: str) -> str:
    value = value.strip()
    if not value.startswith(("http://", "https://", "ftp://")):
        value = "http://" + value
    return value


def _extract_domain(value: str) -> str:
    try:
        from urllib.parse import urlparse
        parsed = urlparse(value if "://" in value else "http://" + value)
        return parsed.netloc or parsed.path.split("/")[0]
    except Exception:
        return value


def _safe_int(val, default=0) -> int:
    try:
        return int(val or default)
    except (TypeError, ValueError):
        return default


def _calculate_url_threat_score(
    db_result, vt, urlscan, otx, whois, dns_result,
    community, gsb=None, lexical=None
) -> tuple:
    """
    Professional weighted threat scoring for URL/Domain/IP analysis.
    Community intel adds a trust-weighted social signal from platform history.
    """
    signals = []

    # 1. Local DB — confirmed offline blacklist (weight 0.25)
    if db_result.get("status") == "found":
        signals.append((0.25, 1.0))

    # 2. VirusTotal — detection ratio (weight 0.27)
    vt_mal = _safe_int(vt.get("malicious"))
    vt_sus = _safe_int(vt.get("suspicious"))
    vt_tot = max(_safe_int(vt.get("total_engines"), 1), 1)
    vt_sig = min((vt_mal + vt_sus * 0.35) / vt_tot, 1.0)
    if vt_sig > 0:
        signals.append((0.27, vt_sig))

    # 3. URLScan.io — live page analysis (weight 0.16)
    if urlscan.get("malicious"):
        signals.append((0.16, 1.0))
    elif urlscan.get("suspicious"):
        signals.append((0.16, 0.50))

    # 4. Community Intel — platform social signal (weight 0.12)
    comm_signal = _safe_int(community.get("signal_score")) if community.get("status") == "found" else 0
    if comm_signal > 0:
        signals.append((0.12, min(comm_signal / 100, 1.0)))

    # 5. OTX — logarithmic pulse scale (weight 0.10)
    pulse_count = _safe_int(otx.get("pulse_count"))
    if pulse_count > 0:
        otx_sig = min(math.log(pulse_count + 1) / math.log(11), 1.0)
        signals.append((0.10, otx_sig))

    # 6. Google Safe Browsing — if available (weight 0.16)
    if gsb and gsb.get("status") == "found":
        signals.append((0.16, 1.0))

    # 7. DNS risk — infrastructure signal (weight 0.05)
    dns_risk = _safe_int(dns_result.get("risk_score"))
    if dns_risk >= 40:
        signals.append((0.05, min(dns_risk / 100, 1.0)))

    # Weighted average
    if not signals:
        base_score = 0.0
    else:
        total_w    = sum(w for w, _ in signals)
        base_score = (sum(w * s for w, s in signals) / total_w) * 100

    # Agreement bonus
    comm_mal   = _safe_int(community.get("malicious_count")) if community.get("status") == "found" else 0
    comm_users = _safe_int(community.get("user_count"), 1)   if community.get("status") == "found" else 1
    strong = sum([
        db_result.get("status") == "found",
        vt_mal >= 3,
        bool(urlscan.get("malicious")),
        bool(gsb and gsb.get("status") == "found"),
        pulse_count >= 3,
        comm_mal >= 2 and comm_users >= 2,
    ])
    if strong >= 4:   base_score = min(base_score * 1.25, 100)
    elif strong == 3: base_score = min(base_score * 1.15, 100)
    elif strong == 2: base_score = min(base_score * 1.08, 100)

    # WHOIS / DNS contextual modifiers — only when base threat exists
    whois_mod = 0.0
    if base_score > 15:
        if whois.get("newly_registered"):  whois_mod += 8.0
        if whois.get("privacy_protected"): whois_mod += 4.0
    base_score = min(base_score + whois_mod, 100)

    dns_mod = 0.0
    if base_score > 15 and dns_risk >= 60:
        dns_mod = (dns_risk - 60) * 0.15
    base_score = min(base_score + dns_mod, 100)

    # Hard floors — confirmed detections
    if db_result.get("status") == "found": base_score = max(base_score, 85)
    if gsb and gsb.get("status") == "found": base_score = max(base_score, 80)
    if vt_mal >= 10:    base_score = max(base_score, 88)
    elif vt_mal >= 5:   base_score = max(base_score, 72)
    elif vt_mal >= 2:   base_score = max(base_score, 50)
    elif vt_mal >= 1:   base_score = max(base_score, 30)
    if urlscan.get("malicious"): base_score = max(base_score, 70)

    # Community floors
    if comm_mal >= 3 and comm_users >= 3:   base_score = max(base_score, 65)
    elif comm_mal >= 2 and comm_users >= 2: base_score = max(base_score, 50)
    elif comm_mal >= 1:                     base_score = max(base_score, 22)

    threat_score = min(int(round(base_score)), 100)

    if threat_score >= 70:   risk = "Critical"
    elif threat_score >= 45: risk = "High"
    elif threat_score >= 20: risk = "Medium"
    else:                    risk = "Low"

    return threat_score, risk


def _aggregate_verdict(engines_list: list) -> str:
    _scores = {"Clean": 0, "Suspicious": 1, "Malicious": 2}
    verdicts = []
    skip = ("unavailable", "not_found", "clean", "error", "pending")
    for eng in engines_list:
        if not isinstance(eng, dict): continue
        if eng.get("status") in skip:  continue
        v = eng.get("verdict", "Clean")
        if v in _scores:
            verdicts.append(v)
    return max(verdicts, key=lambda v: _scores.get(v, 0)) if verdicts else "Clean"


def scan_url(value: str, user_id: int = None) -> dict:
    value      = value.strip()
    input_type = _detect_input_type(value)
    url        = _normalize_url(value)
    domain     = _extract_domain(value)

    resolved_ip = ""
    try:
        resolved_ip = socket.gethostbyname(domain)
    except Exception:
        pass

    # Engine 1: Local DB
    try:
        db_result = lookup_url_db(url, domain)
    except Exception as e:
        db_result = {"engine": "Local DB", "status": "unavailable", "error": str(e)}

    # Engine 2: VirusTotal
    try:
        vt = scan_url_vt(url)
    except Exception as e:
        vt = {"engine": "VirusTotal", "status": "unavailable", "error": str(e)}

    # Engine 3: URLScan.io
    try:
        urlscan = scan_url_urlscan(url)
    except Exception as e:
        urlscan = {"engine": "URLScan.io", "status": "unavailable", "error": str(e)}

    # Engine 4: WHOIS
    try:
        whois = lookup_whois_python(domain)
    except Exception as e:
        try:
            whois = lookup_whois(domain)
        except Exception:
            whois = {"engine": "WHOIS", "status": "unavailable", "error": str(e)}

    # Engine 5: AlienVault OTX
    try:
        otx = lookup_url_otx(domain, input_type)
    except Exception as e:
        otx = {"engine": "AlienVault OTX", "status": "unavailable", "error": str(e)}

    # Engine 6: DNS Intelligence
    try:
        dns_result = get_dns_intel(domain)
    except Exception as e:
        dns_result = {"engine": "DNS Intelligence", "status": "unavailable", "error": str(e)}

    # Engine 7: Community Intel — check both URL and domain
    try:
        community = lookup_community_intel(url.rstrip("/").lower(), "url", user_id)
        if community.get("status") == "not_found":
            comm_domain = lookup_community_intel(domain.lower(), "url", user_id)
            if comm_domain.get("status") == "found":
                community = comm_domain
    except Exception as e:
        community = {"engine": "Community Intel", "status": "unavailable", "error": str(e)}

    # Aggregate verdict
    final_verdict = _aggregate_verdict([db_result, vt, urlscan, otx])
    # Community verdict contributes if confident
    if community.get("status") == "found":
        cv = community.get("verdict", "Clean")
        if cv == "Malicious" and _safe_int(community.get("malicious_count")) >= 2:
            if final_verdict == "Clean":
                final_verdict = "Suspicious"   # escalate but don't override to Malicious alone

    # Threat score
    threat_score, final_risk = _calculate_url_threat_score(
        db_result  = db_result,
        vt         = vt,
        urlscan    = urlscan,
        otx        = otx,
        whois      = whois,
        dns_result = dns_result,
        community  = community,
        gsb        = None,
        lexical    = None,
    )

    # Update community intel after scan
    try:
        tags = list(set(
            (urlscan.get("tags") or []) +
            (otx.get("malware_families") or [])
        ))
        update_community_intel(url.rstrip("/").lower(), "url", final_verdict, threat_score, user_id or 0, tags)
        # Also track at domain level
        if final_verdict in ("Malicious", "Suspicious"):
            update_community_intel(domain.lower(), "url", final_verdict, threat_score, user_id or 0, tags)
    except Exception:
        pass

    # Detection flags — all values None-safe
    flags       = []
    vt_mal_f    = _safe_int(vt.get("malicious"))
    vt_sus_f    = _safe_int(vt.get("suspicious"))
    vt_tot_f    = _safe_int(vt.get("total_engines"))
    pulse_count = _safe_int(otx.get("pulse_count"))

    if db_result.get("status") == "found":
        flags.append(f"[Local DB] Confirmed malicious {db_result.get('category','URL')}: {domain}")
    if vt_mal_f > 0:
        flags.append(f"[VirusTotal] {vt_mal_f}/{vt_tot_f} engines flagged malicious")
    if vt_sus_f > 0:
        flags.append(f"[VirusTotal] {vt_sus_f} engines flagged suspicious")
    if urlscan.get("malicious"):
        flags.append("[URLScan.io] Page classified as malicious")
    elif urlscan.get("suspicious"):
        flags.append("[URLScan.io] Page classified as suspicious")
    if urlscan.get("tags"):
        flags.append(f"[URLScan.io] Tags: {', '.join(urlscan['tags'][:3])}")
    if pulse_count > 0:
        flags.append(f"[OTX] Found in {pulse_count} threat intelligence pulse(s)")
    if otx.get("malware_families"):
        flags.append(f"[OTX] Malware families: {', '.join(otx['malware_families'][:3])}")
    if whois.get("newly_registered"):
        flags.append("[WHOIS] Newly registered domain — high risk context")
    if whois.get("privacy_protected"):
        flags.append("[WHOIS] Registrant identity hidden (privacy protection)")
    for df in (dns_result.get("flags") or []):
        flags.append(f"[DNS] {df}")

    # Community intel flags
    if community.get("status") == "found":
        comm_mal   = _safe_int(community.get("malicious_count"))
        comm_users = _safe_int(community.get("user_count"), 1)
        comm_subs  = _safe_int(community.get("submission_count"))
        if comm_mal >= 2 and comm_users >= 2:
            flags.append(
                f"[Community] ⚠️ Flagged malicious by {comm_users} independent users "
                f"({comm_mal}/{comm_subs} submissions) — confidence: {community.get('confidence','Low')}"
            )
        elif comm_mal >= 1:
            flags.append(
                f"[Community] Previously flagged malicious "
                f"(avg score: {community.get('avg_threat_score',0):.0f}/100)"
            )

    return {
        "input":        value,
        "input_type":   input_type,
        "url":          url,
        "domain":       domain,
        "resolved_ip":  resolved_ip,
        "verdict":      final_verdict,
        "risk":         final_risk,
        "threat_score": threat_score,
        "flags":        flags,
        "engines": {
            "local_db":   db_result,
            "virustotal": vt,
            "urlscan":    urlscan,
            "whois":      whois,
            "otx":        otx,
            "dns":        dns_result,
            "community":  community,
        },
        "summary": {
            "total_engines":   7,
            "vt_detections":   vt.get("detections",   "N/A"),
            "otx_pulses":      pulse_count,
            "urlscan_verdict": urlscan.get("verdict", "N/A"),
            "db_match":        db_result.get("status") == "found",
            "community_subs":  _safe_int(community.get("submission_count")),
        }
    }