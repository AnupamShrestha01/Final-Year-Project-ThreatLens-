"""
backend/services/hash_service.py

Professional hash scanning — 6 engines:
  1. Local MalwareBazaar DB   (offline curated malware)
  2. VirusTotal               (largest AV coverage)
  3. AlienVault OTX           (threat intelligence pulses)
  4. CIRCL hashlookup         (known-good / NSRL exoneration)
  5. MetaDefender             (multi-AV secondary coverage)
  6. Community Intel          (platform-wide social signal)
"""
import sys, os, re, math
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../"))


def detect_hash_type(h: str) -> str:
    h = h.strip().lower()
    if re.fullmatch(r"[0-9a-f]{32}", h): return "md5"
    if re.fullmatch(r"[0-9a-f]{40}", h): return "sha1"
    if re.fullmatch(r"[0-9a-f]{64}", h): return "sha256"
    return "unknown"


def normalize(h: str) -> str:
    return h.strip().lower()


def _safe_int(val, default=0) -> int:
    try:
        return int(val or default)
    except (TypeError, ValueError):
        return default


# ── Engine runners ────────────────────────────────────────────────────────
def _run_local_db(hash_val, hash_type):
    try:
        from backend.threat_intel.malwarebazaar import lookup_hash_mb
        sha256 = hash_val if hash_type == "sha256" else None
        md5    = hash_val if hash_type == "md5"    else None
        return lookup_hash_mb(sha256, md5)
    except Exception as e:
        return {"engine": "MalwareBazaar", "status": "unavailable", "error": str(e)}


def _run_virustotal(hash_val, hash_type):
    try:
        from backend.threat_intel.virustotal import lookup_hash
        return lookup_hash(hash_val)
    except Exception as e:
        return {"engine": "VirusTotal", "status": "unavailable", "error": str(e)}


def _run_otx(hash_val, hash_type):
    try:
        if hash_type != "sha256":
            return {"engine": "AlienVault OTX", "status": "not_applicable",
                    "note": "OTX file indicator lookup requires SHA256"}
        from backend.threat_intel.alienvault_otx import lookup_file_hash
        return lookup_file_hash(hash_val)
    except Exception as e:
        return {"engine": "AlienVault OTX", "status": "unavailable", "error": str(e)}


def _run_circl(hash_val, hash_type):
    try:
        from backend.threat_intel.circl_hashlookup import scan_hash_circl
        return scan_hash_circl(hash_val)
    except Exception as e:
        return {"engine": "CIRCL hashlookup", "status": "unavailable", "error": str(e)}


def _run_metadefender(hash_val, hash_type):
    try:
        from backend.threat_intel.metadefender_hash import scan_hash_metadefender
        return scan_hash_metadefender(hash_val)
    except Exception as e:
        return {"engine": "MetaDefender", "status": "unavailable", "error": str(e)}


# ── Core scoring ──────────────────────────────────────────────────────────
def _calculate_verdict(engines: dict) -> tuple:
    """
    CVSS-style weighted aggregation with:
    - Agreement bonus for multi-engine consensus
    - Logarithmic OTX pulse scaling
    - CIRCL exoneration (subtracts from score)
    - Community intel as supporting social signal
    - Hard floors for confirmed detections
    """
    WEIGHTS = {
        "local_db":     0.23,
        "virustotal":   0.32,
        "metadefender": 0.18,
        "otx":          0.10,
        "circl":        0.07,
        "community":    0.10,
    }

    flags     = []
    local     = engines.get("local_db",     {})
    vt        = engines.get("virustotal",   {})
    md        = engines.get("metadefender", {})
    otx       = engines.get("otx",          {})
    circl     = engines.get("circl",        {})
    community = engines.get("community",    {})

    # Local DB — binary confirmed malware
    D_local = 0.0
    if local.get("status") == "found":
        D_local = 1.0
        flags.append(f"[Local DB] Known malware — {local.get('malware_family','Unknown')}")

    # VirusTotal — detection ratio + suspicious partial credit
    vt_mal = _safe_int(vt.get("malicious"))
    vt_sus = _safe_int(vt.get("suspicious"))
    vt_tot = max(_safe_int(vt.get("total_engines"), 1), 1)
    D_vt   = min((vt_mal + vt_sus * 0.35) / vt_tot, 1.0)
    if vt_mal > 0:
        flags.append(f"[VirusTotal] {vt_mal}/{vt_tot} engines flagged malicious")
    elif vt_sus > 0:
        flags.append(f"[VirusTotal] {vt_sus}/{vt_tot} engines flagged suspicious")

    # MetaDefender — secondary AV ratio
    md_mal = _safe_int(md.get("malicious"))
    md_tot = max(_safe_int(md.get("total_engines"), 1), 1)
    D_md   = min(md_mal / md_tot, 1.0) if md.get("status") == "found" else 0.0
    if D_md > 0:
        flags.append(f"[MetaDefender] {md_mal}/{md_tot} AV engines detected")

    # OTX — logarithmic: 1≈0.28, 3≈0.60, 10=1.0
    D_otx  = 0.0
    pulses = _safe_int(otx.get("pulse_count"))
    if pulses > 0:
        D_otx = min(math.log(pulses + 1) / math.log(11), 1.0)
        flags.append(f"[OTX] Found in {pulses} threat intelligence pulse(s)")

    # CIRCL — known-good exoneration (subtracted)
    D_circl = 0.0
    if circl.get("status") == "found" and circl.get("known_good"):
        trust   = _safe_int(circl.get("trust_score"))
        D_circl = min(trust / 100, 1.0)
        flags.append(f"[CIRCL] Known-good file (trust {trust}/100) — reducing score")

    # Community Intel — social signal from platform history
    D_community = 0.0
    if community.get("status") == "found":
        comm_signal = _safe_int(community.get("signal_score"))
        comm_mal    = _safe_int(community.get("malicious_count"))
        comm_users  = _safe_int(community.get("user_count"), 1)
        D_community = min(comm_signal / 100, 1.0)
        if comm_mal >= 2 and comm_users >= 2:
            flags.append(
                f"[Community] ⚠️ Flagged malicious by {comm_users} independent users "
                f"({comm_mal} times) — confidence: {community.get('confidence','Low')}"
            )
        elif comm_mal >= 1:
            flags.append(
                f"[Community] Previously flagged malicious "
                f"(avg score: {community.get('avg_threat_score',0):.0f}/100)"
            )

    # Weighted aggregation (CIRCL is subtracted)
    raw = (
        WEIGHTS["local_db"]     * D_local      +
        WEIGHTS["virustotal"]   * D_vt         +
        WEIGHTS["metadefender"] * D_md         +
        WEIGHTS["otx"]          * D_otx        +
        WEIGHTS["community"]    * D_community  -
        WEIGHTS["circl"]        * D_circl
    ) * 100

    # Agreement bonus
    detectors = sum([D_local > 0.0, D_vt > 0.05, D_md > 0.05])
    if detectors >= 3:
        raw = min(raw * 1.20, 100)
    elif detectors == 2:
        raw = min(raw * 1.10, 100)

    # Hard floors
    if D_local == 1.0:                          raw = max(raw, 80)
    if vt_mal >= 10:                            raw = max(raw, 88)
    elif vt_mal >= 5:                           raw = max(raw, 72)
    elif D_vt > 0.10 or D_md > 0.10:           raw = max(raw, 45)
    elif D_vt > 0 or D_md > 0:                 raw = max(raw, 25)

    # Community floors
    comm_mal   = _safe_int(community.get("malicious_count")) if community.get("status") == "found" else 0
    comm_users = _safe_int(community.get("user_count"), 1)   if community.get("status") == "found" else 1
    if comm_mal >= 3 and comm_users >= 3:       raw = max(raw, 60)
    elif comm_mal >= 2 and comm_users >= 2:     raw = max(raw, 45)
    elif comm_mal >= 1:                         raw = max(raw, 20)

    # CIRCL exoneration cap — only when no AV hits and no community flags
    if D_circl >= 0.75 and D_local == 0.0 and D_vt < 0.05 and D_md < 0.05 and comm_mal == 0:
        raw = min(raw, 25)

    score = round(min(max(raw, 0.0), 100.0), 2)

    if score >= 70:   verdict, risk = "Malicious",  "Critical"
    elif score >= 45: verdict, risk = "Suspicious", "High"
    elif score >= 20: verdict, risk = "Suspicious", "Medium"
    else:             verdict, risk = "Clean",       "Low"

    return verdict, risk, score, flags


def _get_threat_type(engines: dict) -> str:
    local = engines.get("local_db",     {})
    vt    = engines.get("virustotal",   {})
    md    = engines.get("metadefender", {})

    for source_name in [local.get("malware_type"), local.get("malware_family")]:
        if not source_name: continue
        fam = source_name.lower()
        if "ransom"   in fam: return "Ransomware"
        if "trojan"   in fam: return "Trojan"
        if "rat"      in fam: return "Remote Access Trojan"
        if "miner"    in fam: return "Cryptominer"
        if "loader"   in fam: return "Malware Loader"
        if "stealer"  in fam: return "Info Stealer"
        if "banker"   in fam: return "Banking Trojan"
        if "worm"     in fam: return "Worm"
        if "backdoor" in fam: return "Backdoor"
        if "bot"      in fam: return "Botnet"
        if "rootkit"  in fam: return "Rootkit"
        return source_name

    if vt.get("threat_names"):
        tn = " ".join(vt["threat_names"]).lower()
        for k, v in [("ransom","Ransomware"),("trojan","Trojan"),("backdoor","Backdoor"),
                     ("miner","Cryptominer"),("stealer","Info Stealer"),("worm","Worm")]:
            if k in tn: return v

    if md.get("threat_name"):
        tn = md["threat_name"].lower()
        for k, v in [("ransom","Ransomware"),("trojan","Trojan"),("backdoor","Backdoor")]:
            if k in tn: return v

    return "Unknown"


def _get_mitre_techniques(malware_family: str, engines: dict) -> list:
    try:
        from backend.threat_intel.mitre_mapper import map_mitre_from_family, map_mitre_from_tags
        techniques = map_mitre_from_family(malware_family)
        tags = (
            engines.get("local_db",   {}).get("tags", []) +
            engines.get("virustotal", {}).get("tags", [])
        )
        for t in map_mitre_from_tags(tags):
            if t not in techniques:
                techniques.append(t)
        return techniques
    except Exception:
        return []


def scan_hash(hash_val: str, user_id=None) -> dict:
    hash_val  = normalize(hash_val)
    hash_type = detect_hash_type(hash_val)

    if hash_type == "unknown":
        return {
            "success": False,
            "verdict": "Invalid",
            "message": (
                f"Invalid hash format. Expected MD5 (32), SHA1 (40), or SHA256 (64) "
                f"hex characters. Got {len(hash_val)} chars."
            )
        }

    # Run all engines
    local_result  = _run_local_db(hash_val,     hash_type)
    vt_result     = _run_virustotal(hash_val,   hash_type)
    otx_result    = _run_otx(hash_val,          hash_type)
    circl_result  = _run_circl(hash_val,        hash_type)
    md_result     = _run_metadefender(hash_val, hash_type)

    # Community Intel
    try:
        from backend.threat_intel.community_intel import lookup_community_intel, update_community_intel
        community_result = lookup_community_intel(hash_val, "hash", user_id)
    except Exception as e:
        community_result = {"engine": "Community Intel", "status": "unavailable", "error": str(e)}

    engines = {
        "local_db":     local_result,
        "virustotal":   vt_result,
        "otx":          otx_result,
        "circl":        circl_result,
        "metadefender": md_result,
        "community":    community_result,
    }

    verdict, risk, score, flags = _calculate_verdict(engines)
    threat_type    = _get_threat_type(engines)
    malware_family = (
        local_result.get("malware_family")
        or (vt_result.get("threat_names", [None])[0] if vt_result.get("threat_names") else None)
        or (md_result.get("threat_name")              if md_result.get("threat_name")  else None)
        or "Unknown"
    )
    mitre_techniques = _get_mitre_techniques(malware_family, engines)

    # Update community intel after scan
    try:
        from backend.threat_intel.community_intel import update_community_intel
        tags = list(set(
            (vt_result.get("tags") or []) +
            ([malware_family] if malware_family != "Unknown" else [])
        ))
        update_community_intel(hash_val, "hash", verdict, int(score), user_id or 0, tags)
    except Exception:
        pass

    circl_info = None
    if circl_result.get("status") == "found" and circl_result.get("known_good"):
        circl_info = {
            "trust_score":     _safe_int(circl_result.get("trust_score")),
            "file_name":       circl_result.get("file_name",       ""),
            "product_name":    circl_result.get("product_name",    ""),
            "product_version": circl_result.get("product_version", ""),
            "os":              circl_result.get("os",              ""),
            "source":          circl_result.get("source",          "NSRL"),
        }

    return {
        "success":          True,
        "input":            hash_val,
        "hash_type":        hash_type.upper(),
        "verdict":          verdict,
        "risk":             risk,
        "threat_score":     score,
        "threat_type":      threat_type,
        "malware_family":   malware_family,
        "flags":            flags,
        "mitre_techniques": mitre_techniques,
        "circl_info":       circl_info,
        "engines":          engines,
    }