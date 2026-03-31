"""
backend/threat_intel/virustotal.py
VirusTotal v3 API — vendor table + behavior sandbox
"""
import os, json, hashlib, time
import urllib.request, urllib.error

VT_BASE = "https://www.virustotal.com/api/v3"


def _vt_get_key():
    return os.environ.get("VT_API_KEY", "")


def _vt_request(endpoint, method="GET", data=None, headers_extra=None):
    api_key = _vt_get_key()
    if not api_key:
        return {"error": "VT_API_KEY not configured"}
    headers = {"x-apikey": api_key, "accept": "application/json"}
    if headers_extra:
        headers.update(headers_extra)
    try:
        req = urllib.request.Request(VT_BASE + endpoint, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = ""
        try: body = e.read().decode()
        except: pass
        return {"error": f"HTTP {e.code}: {e.reason}", "body": body}
    except Exception as e:
        return {"error": str(e)}


def _parse_vt_response(result):
    try:
        data = result.get("data") or {}
        attrs = data.get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        engines_raw = attrs.get("last_analysis_results") or {}

        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)
        total      = sum(stats.values()) if stats else 0
        detections = malicious + suspicious

        # Vendor table
        vendor_table = []
        for engine_name, engine_data in engines_raw.items():
            if not isinstance(engine_data, dict):
                continue
            vendor_table.append({
                "vendor":   engine_name,
                "category": engine_data.get("category") or "undetected",
                "result":   engine_data.get("result") or "",
                "method":   engine_data.get("method") or "",
                "version":  engine_data.get("engine_version") or "",
            })
        order = {"malicious": 0, "suspicious": 1, "type-unsupported": 2, "timeout": 3, "undetected": 4}
        vendor_table.sort(key=lambda x: order.get(x["category"], 5))

        verdict = "Clean"
        if malicious >= 5:    verdict = "Malicious"
        elif malicious >= 1:  verdict = "Suspicious"
        elif suspicious >= 3: verdict = "Suspicious"

        # Safe threat_names — no set comprehension to avoid unhashable errors
        threat_names = []
        seen = set()
        for v in engines_raw.values():
            if not isinstance(v, dict):
                continue
            r = v.get("result")
            if r and v.get("category") in ("malicious", "suspicious") and r not in seen:
                seen.add(r)
                threat_names.append(r)

        return {
            "engine":        "VirusTotal",
            "status":        "found",
            "verdict":       verdict,
            "detections":    f"{detections}/{total}",
            "malicious":     malicious,
            "suspicious":    suspicious,
            "undetected":    undetected,
            "total_engines": total,
            "threat_names":  threat_names[:8],
            "vendor_table":  vendor_table,
            "file_type":     attrs.get("type_description") or "",
            "first_seen":    attrs.get("first_submission_date") or "",
            "last_analysis": attrs.get("last_analysis_date") or "",
            "tags":          attrs.get("tags") or [],
        }
    except Exception as e:
        return {"engine": "VirusTotal", "status": "parse_error", "error": str(e)}


def _get_behavior(sha256):
    """Fetch VT sandbox behavior data."""
    try:
        result = _vt_request(f"/files/{sha256}/behaviour_summary")
        if not result or "error" in result:
            return {"engine": "VT Behavior", "status": "not_found"}

        # Safe data extraction — guard against None at every level
        raw_data = result.get("data")
        if raw_data is None:
            return {"engine": "VT Behavior", "status": "not_found"}
        attr = raw_data if isinstance(raw_data, dict) else {}

        # Verdict from sandbox_verdicts
        verdict = "Clean"
        sb = attr.get("sandbox_verdicts") or {}
        if isinstance(sb, dict):
            for v in sb.values():
                if not isinstance(v, dict):
                    continue
                cat = (v.get("category") or "").lower()
                if cat == "malicious":
                    verdict = "Malicious"
                    break
                elif cat == "suspicious" and verdict != "Malicious":
                    verdict = "Suspicious"

        # Network
        network = []
        for ip in (attr.get("ip_traffic") or [])[:8]:
            if not isinstance(ip, dict): continue
            val = ip.get("destination_ip") or ""
            if val: network.append({"type": "IP", "value": val})
        for dns in (attr.get("dns_lookups") or [])[:8]:
            if not isinstance(dns, dict): continue
            val = dns.get("hostname") or ""
            if val: network.append({"type": "Domain", "value": val})
        for http in (attr.get("http_conversations") or [])[:5]:
            if not isinstance(http, dict): continue
            val = http.get("url") or ""
            if val: network.append({"type": "URL", "value": val})

        # Files
        file_activity = []
        for f in (attr.get("files_written") or [])[:5]:
            item = f if isinstance(f, str) else str(f)
            if item: file_activity.append(item)
        for f in (attr.get("files_dropped") or [])[:5]:
            name = f if isinstance(f, str) else (f.get("path") if isinstance(f, dict) else str(f))
            if name and name not in file_activity:
                file_activity.append(name)

        # Processes
        processes = []
        for p in (attr.get("processes_created") or [])[:8]:
            if isinstance(p, dict):
                processes.append({
                    "name":    p.get("name") or p.get("process_name") or "",
                    "command": (p.get("cmd") or p.get("command_line") or "")[:80],
                })
            else:
                processes.append({"name": str(p), "command": ""})

        # Behavioral tags
        signatures = []
        for s in (attr.get("behaviour_tags") or [])[:10]:
            name = s if isinstance(s, str) else (s.get("name") if isinstance(s, dict) else str(s))
            if name:
                signatures.append({"name": name, "severity": "medium"})

        # MITRE
        mitre = []
        for t in (attr.get("attack_techniques") or [])[:6]:
            if isinstance(t, dict):
                mitre.append(f"{t.get('id','')} {t.get('name','')}".strip())
            elif t:
                mitre.append(str(t))

        # Sandboxes
        sandboxes = []
        if isinstance(sb, dict):
            for v in sb.values():
                if not isinstance(v, dict): continue
                sname = v.get("sandbox_name") or ""
                if sname and sname not in sandboxes:
                    sandboxes.append(sname)

        return {
            "engine":        "VT Behavior",
            "status":        "found",
            "verdict":       verdict,
            "environment":   ", ".join(sandboxes[:3]) if sandboxes else "VirusTotal Sandbox",
            "network":       [n for n in network if n.get("value")],
            "file_activity": [f for f in file_activity if f][:8],
            "processes":     processes,
            "signatures":    signatures,
            "mitre_attcks":  [m for m in mitre if m.strip()],
        }
    except Exception as e:
        return {"engine": "VT Behavior", "status": "unavailable", "error": str(e)}


def lookup_hash(sha256):
    result = _vt_request(f"/files/{sha256}")
    if not result or "error" in result:
        return {"engine": "VirusTotal", "status": "unavailable",
                "error": (result or {}).get("error", "Unknown error")}
    return _parse_vt_response(result)


def scan_file_vt(file_data, filename="file"):
    """Hash lookup first, upload if not found. Also fetches behavior."""
    sha256 = hashlib.sha256(file_data).hexdigest()

    lookup = lookup_hash(sha256)
    if lookup.get("status") == "found":
        lookup["behavior"] = _get_behavior(sha256)
        return lookup

    api_key = _vt_get_key()
    if not api_key:
        return {"engine": "VirusTotal", "status": "unavailable",
                "error": "API key not configured", "behavior": {"engine": "VT Behavior", "status": "not_found"}}

    # Upload file
    boundary = "----ThreatLensBoundary7x"
    body  = f'--{boundary}\r\n'.encode()
    body += f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode()
    body += b'Content-Type: application/octet-stream\r\n\r\n'
    body += file_data
    body += f'\r\n--{boundary}--\r\n'.encode()

    upload = _vt_request("/files", method="POST", data=body,
        headers_extra={"Content-Type": f"multipart/form-data; boundary={boundary}"})

    if not upload or "error" in upload:
        return {"engine": "VirusTotal", "status": "upload_failed",
                "error": (upload or {}).get("error", "Upload failed"),
                "behavior": {"engine": "VT Behavior", "status": "not_found"}}

    analysis_id = (upload.get("data") or {}).get("id", "")
    if not analysis_id:
        return {"engine": "VirusTotal", "status": "submitted",
                "message": "File submitted.",
                "behavior": {"engine": "VT Behavior", "status": "not_found"}}

    # Poll for result
    for _ in range(4):
        time.sleep(8)
        poll   = _vt_request(f"/analyses/{analysis_id}")
        status = ((poll.get("data") or {}).get("attributes") or {}).get("status", "")
        if status == "completed":
            result = lookup_hash(sha256)
            result["behavior"] = _get_behavior(sha256)
            return result

    return {"engine": "VirusTotal", "status": "pending",
            "message": "Analysis submitted — retry in ~1 minute.",
            "behavior": {"engine": "VT Behavior", "status": "not_found"}}


# ── URL Scan ──────────────────────────────────────────────────────────────
def scan_url_vt(url: str) -> dict:
    """Submit URL to VirusTotal and get scan results."""
    import base64, urllib.parse

    # First try direct URL lookup using URL identifier
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    result = _vt_request(f"/urls/{url_id}")

    if "error" not in result and result.get("data"):
        return _parse_vt_url_response(result)

    # If not found, submit for scanning
    data = urllib.parse.urlencode({"url": url}).encode()
    submit = _vt_request("/urls", method="POST", data=data,
        headers_extra={"Content-Type": "application/x-www-form-urlencoded"})

    if "error" in submit:
        return {"engine": "VirusTotal", "status": "unavailable", "error": submit["error"]}

    analysis_id = (submit.get("data") or {}).get("id", "")
    if not analysis_id:
        return {"engine": "VirusTotal", "status": "submitted", "message": "URL submitted for analysis."}

    # Poll for result
    import time
    for _ in range(3):
        time.sleep(5)
        poll = _vt_request(f"/analyses/{analysis_id}")
        status = ((poll.get("data") or {}).get("attributes") or {}).get("status", "")
        if status == "completed":
            # Re-fetch the URL report
            result2 = _vt_request(f"/urls/{url_id}")
            if "error" not in result2 and result2.get("data"):
                return _parse_vt_url_response(result2)

    return {"engine": "VirusTotal", "status": "pending",
            "message": "Analysis submitted — results pending."}


def _parse_vt_url_response(result: dict) -> dict:
    """Parse VirusTotal URL scan response."""
    try:
        attrs = (result.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        engines_raw = attrs.get("last_analysis_results") or {}

        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)
        total      = sum(stats.values()) if stats else 0
        detections = malicious + suspicious

        verdict = "Clean"
        if malicious >= 3:   verdict = "Malicious"
        elif malicious >= 1: verdict = "Suspicious"
        elif suspicious >= 3: verdict = "Suspicious"

        # Vendor table
        vendor_table = []
        for engine_name, engine_data in engines_raw.items():
            if not isinstance(engine_data, dict): continue
            cat = (engine_data.get("category") or "undetected").lower()
            vendor_table.append({
                "vendor":   engine_name,
                "category": cat,
                "result":   engine_data.get("result") or cat,
            })
        order = {"malicious":0,"phishing":1,"suspicious":2,"harmless":3,"undetected":4}
        vendor_table.sort(key=lambda x: order.get(x["category"], 5))

        categories = attrs.get("categories") or {}
        tags = list(set(list(categories.values())))[:6]

        return {
            "engine":        "VirusTotal",
            "status":        "found",
            "verdict":       verdict,
            "detections":    f"{detections}/{total}",
            "malicious":     malicious,
            "suspicious":    suspicious,
            "undetected":    undetected,
            "total_engines": total,
            "vendor_table":  vendor_table,
            "tags":          tags,
            "url":           attrs.get("url") or "",
            "title":         attrs.get("title") or "",
            "final_url":     attrs.get("last_final_url") or "",
            "last_analysis": attrs.get("last_analysis_date") or "",
        }
    except Exception as e:
        return {"engine": "VirusTotal", "status": "parse_error", "error": str(e)}