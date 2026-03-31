"""
backend/services/file_service.py
7 engines: Static Analysis, YARA, VirusTotal (+Behavior), AlienVault OTX,
           MalwareBazaar, PE Analysis, MITRE ATT&CK, Community Intel
"""
import sys, os, math
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))

from backend.engines.static_analysis    import analyze_file
from backend.engines.yara_engine        import scan_with_yara
from backend.threat_intel.virustotal    import scan_file_vt
from backend.threat_intel.alienvault_otx import lookup_file_hash as otx_lookup
from backend.threat_intel.malwarebazaar import lookup_hash_mb
from backend.threat_intel.pe_analysis   import analyze_pe
from backend.threat_intel.mitre_mapper  import map_to_mitre
from backend.threat_intel.community_intel import lookup_community_intel, update_community_intel

_VERDICT_SCORE = {"Clean": 0, "Potentially Unwanted": 1, "Suspicious": 2, "Malicious": 3}


def _safe_int(val, default=0) -> int:
    try:
        return int(val or default)
    except (TypeError, ValueError):
        return default


def _aggregate_verdict(verdicts: list) -> str:
    return max(verdicts, key=lambda v: _VERDICT_SCORE.get(v, 0)) if verdicts else "Clean"


def _calculate_file_threat_score(static, yara, vt, otx, behavior, mb, pe, community) -> tuple:
    """
    Professional weighted threat scoring for file analysis.
    Engines contribute normalised signals [0.0-1.0] combined via
    weighted average. Agreement bonus rewards multi-engine consensus.
    Community intel adds a trust-weighted social signal.
    """
    signals = []

    # MalwareBazaar — confirmed curated malware DB (weight 0.22)
    if mb.get("status") == "found":
        signals.append((0.22, 1.0))

    # VirusTotal — detection ratio + suspicious partial credit (weight 0.26)
    vt_mal = _safe_int(vt.get("malicious"))
    vt_sus = _safe_int(vt.get("suspicious"))
    vt_tot = max(_safe_int(vt.get("total_engines"), 1), 1)
    vt_sig = min((vt_mal + vt_sus * 0.35) / vt_tot, 1.0)
    if vt_sig > 0:
        signals.append((0.26, vt_sig))

    # YARA — logarithmic: 1 rule≈0.43, 5 rules=1.0 (weight 0.17)
    yara_hits = _safe_int(yara.get("matched_count"))
    if yara_hits > 0:
        yara_sig = min(math.log(yara_hits + 1) / math.log(6), 1.0)
        signals.append((0.17, yara_sig))

    # VT Sandbox behavior — dynamic execution evidence (weight 0.13)
    beh_verdict = behavior.get("verdict", "Clean") if isinstance(behavior, dict) else "Clean"
    beh_sig = {"Malicious": 1.0, "Suspicious": 0.55, "Potentially Unwanted": 0.30}.get(beh_verdict, 0.0)
    if beh_sig > 0:
        signals.append((0.13, beh_sig))

    # Community Intel — platform-wide social signal (weight 0.10)
    comm_signal = _safe_int(community.get("signal_score")) if community.get("status") == "found" else 0
    if comm_signal > 0:
        signals.append((0.10, min(comm_signal / 100, 1.0)))

    # Static analysis — entropy, strings, structural (weight 0.07)
    static_score = _safe_int(static.get("threat_score"))
    if static_score > 0:
        signals.append((0.07, min(static_score / 100, 1.0)))

    # PE analysis — structural risk (weight 0.07)
    pe_risk = _safe_int(pe.get("risk_score")) if pe.get("status") == "analyzed" else 0
    if pe_risk > 0:
        signals.append((0.07, min(pe_risk / 100, 1.0)))

    # OTX pulses — logarithmic (weight 0.06)
    pulse_count = _safe_int(otx.get("pulse_count"))
    if pulse_count > 0:
        otx_sig = min(math.log(pulse_count + 1) / math.log(11), 1.0)
        signals.append((0.06, otx_sig))

    # Weighted average
    if not signals:
        raw_score = 0.0
    else:
        total_w   = sum(w for w, _ in signals)
        raw_score = (sum(w * s for w, s in signals) / total_w) * 100

    # Agreement bonus — independent sources confirming each other
    strong = sum([
        mb.get("status") == "found",
        vt_mal >= 3,
        yara_hits >= 2,
        beh_verdict == "Malicious",
        pe_risk >= 70,
        community.get("status") == "found" and _safe_int(community.get("malicious_count")) >= 2,
    ])
    if strong >= 4:
        raw_score = min(raw_score * 1.30, 100)
    elif strong == 3:
        raw_score = min(raw_score * 1.20, 100)
    elif strong == 2:
        raw_score = min(raw_score * 1.10, 100)

    # Hard floors
    if mb.get("status") == "found":          raw_score = max(raw_score, 85)
    if vt_mal >= 10:                          raw_score = max(raw_score, 90)
    elif vt_mal >= 5:                         raw_score = max(raw_score, 75)
    elif vt_mal >= 2:                         raw_score = max(raw_score, 50)
    elif vt_mal >= 1:                         raw_score = max(raw_score, 30)
    if beh_verdict == "Malicious":            raw_score = max(raw_score, 70)
    if yara_hits >= 3:                        raw_score = max(raw_score, 60)
    # Community floor — 2+ users independently flagged malicious
    comm_mal = _safe_int(community.get("malicious_count")) if community.get("status") == "found" else 0
    comm_users = _safe_int(community.get("user_count"),  1) if community.get("status") == "found" else 1
    if comm_mal >= 2 and comm_users >= 2:     raw_score = max(raw_score, 55)
    elif comm_mal >= 1:                       raw_score = max(raw_score, 25)

    threat_score = min(int(round(raw_score)), 100)

    if threat_score >= 70:   risk = "Critical"
    elif threat_score >= 45: risk = "High"
    elif threat_score >= 20: risk = "Medium"
    else:                    risk = "Low"

    return threat_score, risk


def scan_file(file_data: bytes, filename: str = "", user_id: int = None) -> dict:

    # Engine 1: Static Analysis
    try:
        static = analyze_file(file_data, filename)
    except Exception as e:
        static = {"engine": "Static Analysis", "status": "error", "error": str(e),
                  "verdict": "Clean", "threat_score": 0, "flags": [],
                  "hashes": {}, "entropy": 0, "file_type": "Unknown"}

    sha256 = static.get("hashes", {}).get("sha256", "")
    md5    = static.get("hashes", {}).get("md5",    "")

    # Engine 2: YARA Rules
    try:
        yara = scan_with_yara(file_data)
    except Exception as e:
        yara = {"engine": "YARA", "status": "error", "error": str(e),
                "verdict": "Clean", "matched_count": 0, "matches": []}

    # Engine 3: VirusTotal + Behavior
    try:
        vt = scan_file_vt(file_data, filename)
    except Exception as e:
        vt = {"engine": "VirusTotal", "status": "unavailable", "error": str(e)}

    behavior = vt.pop("behavior", None) if isinstance(vt, dict) else None
    if not behavior:
        behavior = {"engine": "VT Behavior", "status": "not_found"}

    # Engine 4: AlienVault OTX
    try:
        otx = otx_lookup(sha256) if sha256 else {"engine": "AlienVault OTX", "status": "unavailable"}
    except Exception as e:
        otx = {"engine": "AlienVault OTX", "status": "unavailable", "error": str(e)}

    # Engine 5: MalwareBazaar
    try:
        mb = lookup_hash_mb(sha256, md5) if sha256 else {"engine": "MalwareBazaar", "status": "unavailable"}
    except Exception as e:
        mb = {"engine": "MalwareBazaar", "status": "unavailable", "error": str(e)}

    # Engine 6: PE Analysis
    try:
        pe = analyze_pe(file_data, filename)
    except Exception as e:
        pe = {"engine": "PE Analysis", "status": "unavailable", "error": str(e)}

    # Engine 7: MITRE ATT&CK Mapping
    try:
        vt_mitre = behavior.get("mitre_attcks", []) if isinstance(behavior, dict) else []
        mitre = map_to_mitre(
            pe_result     = pe,
            yara_result   = yara,
            static_result = static,
            vt_mitre      = vt_mitre,
        )
    except Exception as e:
        mitre = {"techniques": [], "tactic_summary": {}, "total": 0, "error": str(e)}

    # Engine 8: Community Intel
    # Check both SHA256 and filename for community signals
    community = {"engine": "Community Intel", "status": "not_found", "signal_score": 0}
    try:
        if sha256:
            community = lookup_community_intel(sha256, "hash", user_id)
        # If hash not found, try filename as secondary lookup
        if community.get("status") == "not_found" and filename:
            comm_by_name = lookup_community_intel(filename.lower(), "file", user_id)
            if comm_by_name.get("status") == "found":
                community = comm_by_name
    except Exception as e:
        community = {"engine": "Community Intel", "status": "unavailable", "error": str(e)}

    # Aggregate Verdict
    active_verdicts = [
        static.get("verdict",  "Clean"),
        yara.get("verdict",    "Clean"),
    ]
    if pe.get("status") == "analyzed" and pe.get("verdict"):
        active_verdicts.append(pe["verdict"])
    for engine in [vt, otx, behavior, mb]:
        if not isinstance(engine, dict): continue
        if engine.get("status") not in ("unavailable","pending","submitted","not_found","clean","error"):
            v = engine.get("verdict", "Clean")
            if v in _VERDICT_SCORE:
                active_verdicts.append(v)
    # Community verdict also contributes
    if community.get("status") == "found":
        cv = community.get("verdict", "Clean")
        if cv in _VERDICT_SCORE and _VERDICT_SCORE[cv] >= 2:  # only Malicious/Suspicious
            active_verdicts.append(cv)

    final_verdict = _aggregate_verdict(active_verdicts)

    # Threat Score
    threat_score, final_risk = _calculate_file_threat_score(
        static, yara, vt, otx, behavior, mb, pe, community
    )

    # Update community intel AFTER scoring (async-style — non-blocking)
    try:
        if sha256 and final_verdict != "Invalid":
            tags = list(set(
                (vt.get("tags") or []) +
                (mb.get("tags") or []) +
                ([mb.get("malware_family")] if mb.get("malware_family") else [])
            ))
            update_community_intel(sha256, "hash", final_verdict, threat_score, user_id or 0, tags)
        if filename and final_verdict in ("Malicious", "Suspicious"):
            update_community_intel(filename.lower(), "file", final_verdict, threat_score, user_id or 0)
    except Exception:
        pass

    # Detection Flags
    all_flags = list(static.get("flags", []))

    for m in (yara.get("matches") or []):
        if isinstance(m, dict):
            all_flags.append(f"[YARA] {m.get('rule','')}: {m.get('description','')}")

    vt_mal_f = _safe_int(vt.get("malicious"))
    vt_tot_f = _safe_int(vt.get("total_engines"))
    if vt_mal_f > 0:
        all_flags.append(f"[VirusTotal] {vt_mal_f}/{vt_tot_f} engines flagged malicious")
    if vt.get("threat_names"):
        all_flags.append(f"[VirusTotal] Threat: {', '.join(vt['threat_names'][:3])}")

    pulse_count = _safe_int(otx.get("pulse_count"))
    if pulse_count > 0:
        all_flags.append(f"[OTX] Referenced in {pulse_count} threat intelligence pulse(s)")
    if otx.get("malware_families"):
        all_flags.append(f"[OTX] Malware family: {', '.join(otx['malware_families'][:3])}")
    if otx.get("adversaries"):
        all_flags.append(f"[OTX] Known adversary: {', '.join(otx['adversaries'][:2])}")

    beh_verdict = behavior.get("verdict", "") if isinstance(behavior, dict) else ""
    if beh_verdict in ("Malicious", "Suspicious"):
        all_flags.append(f"[Sandbox] Behavioral verdict: {beh_verdict}")
    if isinstance(behavior, dict):
        if behavior.get("network"):
            all_flags.append(f"[Sandbox] Network activity: {len(behavior['network'])} connection(s)")
        if behavior.get("signatures"):
            all_flags.append(f"[Sandbox] {len(behavior['signatures'])} behavioral tag(s) found")
        if behavior.get("mitre_attcks"):
            all_flags.append(f"[Sandbox] MITRE ATT&CK: {', '.join(behavior['mitre_attcks'][:3])}")

    if mb.get("status") == "found":
        all_flags.append(f"[MalwareBazaar] Known malware: {mb.get('malware_family','Unknown')}")
        if mb.get("tags"):
            all_flags.append(f"[MalwareBazaar] Tags: {', '.join(mb['tags'][:4])}")
        if mb.get("source") == "local_db":
            all_flags.append("[MalwareBazaar] ⚡ Matched in local malware hash database")

    if mitre.get("total", 0) > 0:
        tids = [t["id"] for t in mitre["techniques"][:4]]
        all_flags.append(f"[MITRE] {mitre['total']} ATT&CK technique(s) mapped: {', '.join(tids)}")

    for pf in (pe.get("flags") or []):
        all_flags.append(f"[PE] {pf}")
    if pe.get("packers"):
        all_flags.append(f"[PE] Packer detected: {', '.join(pe['packers'])}")
    if pe.get("suspicious_imports"):
        crit = [x["function"] for x in pe["suspicious_imports"] if x.get("severity") == "critical"]
        if crit:
            all_flags.append(f"[PE] Critical imports: {', '.join(crit[:4])}")

    # Community intel flags
    if community.get("status") == "found":
        comm_mal   = _safe_int(community.get("malicious_count"))
        comm_users = _safe_int(community.get("user_count"), 1)
        comm_subs  = _safe_int(community.get("submission_count"))
        if comm_mal >= 2 and comm_users >= 2:
            all_flags.append(
                f"[Community] ⚠️ Flagged malicious by {comm_users} independent users "
                f"({comm_mal}/{comm_subs} submissions) — confidence: {community.get('confidence','Low')}"
            )
        elif comm_mal >= 1:
            all_flags.append(
                f"[Community] Previously flagged malicious "
                f"(avg score: {community.get('avg_threat_score',0):.0f}/100)"
            )

    return {
        "filename":     filename,
        "file_size":    len(file_data),
        "file_type":    static.get("file_type", "Unknown"),
        "hashes":       static.get("hashes", {}),
        "entropy":      static.get("entropy", 0),
        "verdict":      final_verdict,
        "risk":         final_risk,
        "threat_score": threat_score,
        "flags":        all_flags,
        "engines": {
            "static_analysis": static,
            "yara":            yara,
            "virustotal":      vt,
            "otx":             otx,
            "behavior":        behavior,
            "malwarebazaar":   mb,
            "pe_analysis":     pe,
            "mitre":           mitre,
            "community":       community,
        },
        "summary": {
            "total_engines":  8,
            "yara_matches":   yara.get("matched_count", 0),
            "vt_detections":  vt.get("detections", "N/A"),
            "otx_pulses":     pulse_count,
            "mb_status":      mb.get("status", "N/A"),
            "community_subs": _safe_int(community.get("submission_count")),
        }
    }