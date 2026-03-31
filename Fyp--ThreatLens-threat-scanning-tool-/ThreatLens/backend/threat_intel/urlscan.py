"""
backend/threat_intel/urlscan.py
URLScan.io — free URL scanner (no API key needed for search)
Submit URL for scanning + fetch results
"""
import os, json, time, urllib.request, urllib.error, urllib.parse

URLSCAN_BASE = "https://urlscan.io/api/v1"
URLSCAN_API_KEY = os.environ.get("URLSCAN_API_KEY", "")


def _request(endpoint, method="GET", data=None, headers_extra=None):
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if URLSCAN_API_KEY:
        headers["API-Key"] = URLSCAN_API_KEY
    if headers_extra:
        headers.update(headers_extra)
    try:
        req = urllib.request.Request(
            URLSCAN_BASE + endpoint,
            data=json.dumps(data).encode() if data else None,
            headers=headers,
            method=method
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode())
            return {"error": f"HTTP {e.code}", "detail": body}
        except:
            return {"error": f"HTTP {e.code}"}
    except Exception as e:
        return {"error": str(e)}


def scan_url_urlscan(url: str) -> dict:
    """
    1. Search URLScan.io for existing results on this URL/domain
    2. If found return latest result
    3. If not found and API key present, submit for new scan
    """
    # Extract domain for search
    try:
        from urllib.parse import urlparse
        domain = urlparse(url).netloc or url
    except:
        domain = url

    # Step 1: Search for existing scans
    query = urllib.parse.quote(f"domain:{domain}")
    search = _request(f"/search/?q={query}&size=1&sort=date:desc")

    if "error" not in search and search.get("results"):
        result = search["results"][0]
        return _parse_urlscan_result(result)

    # Step 2: Submit new scan if API key available
    if URLSCAN_API_KEY:
        submit = _request("/scan/", method="POST", data={
            "url": url,
            "visibility": "public"
        })
        if "error" in submit:
            return {"engine": "URLScan.io", "status": "unavailable", "error": submit["error"]}

        uuid = submit.get("uuid", "")
        if not uuid:
            return {"engine": "URLScan.io", "status": "unavailable", "error": "No UUID returned"}

        # Poll for result
        for _ in range(4):
            time.sleep(8)
            result = _request(f"/result/{uuid}/")
            if "error" not in result and result.get("page"):
                return _parse_urlscan_result(result)

        return {"engine": "URLScan.io", "status": "pending",
                "message": "Scan submitted — check back later.",
                "uuid": uuid,
                "report_url": f"https://urlscan.io/result/{uuid}/"}

    return {"engine": "URLScan.io", "status": "not_found", "verdict": "Clean"}


def _parse_urlscan_result(result: dict) -> dict:
    """Parse URLScan.io result."""
    try:
        page   = result.get("page") or {}
        stats  = result.get("stats") or {}
        verdicts = result.get("verdicts") or {}
        overall  = verdicts.get("overall") or {}
        meta     = result.get("meta") or {}

        is_malicious  = overall.get("malicious", False)
        is_suspicious = False
        score = overall.get("score", 0)
        if score and score > 50:
            is_suspicious = True

        tags = overall.get("tags") or []
        categories = overall.get("categories") or []

        verdict = "Clean"
        if is_malicious:   verdict = "Malicious"
        elif is_suspicious: verdict = "Suspicious"

        return {
            "engine":      "URLScan.io",
            "status":      "found",
            "verdict":     verdict,
            "malicious":   is_malicious,
            "suspicious":  is_suspicious,
            "score":       score,
            "tags":        (tags + categories)[:6],
            "page_title":  page.get("title") or "",
            "page_url":    page.get("url") or "",
            "final_url":   page.get("url") or "",
            "ip":          page.get("ip") or "",
            "country":     page.get("country") or "",
            "server":      page.get("server") or "",
            "screenshot":  result.get("task", {}).get("screenshotURL") or "",
            "report_url":  f"https://urlscan.io/result/{result.get('task',{}).get('uuid','')}/",
            "asn":         page.get("asnname") or "",
            "tls_issuer":  (meta.get("processors") or {}).get("certstream", {}).get("data", [{}])[0].get("issuer", "") if isinstance((meta.get("processors") or {}).get("certstream", {}).get("data"), list) else "",
        }
    except Exception as e:
        return {"engine": "URLScan.io", "status": "parse_error", "error": str(e)}
