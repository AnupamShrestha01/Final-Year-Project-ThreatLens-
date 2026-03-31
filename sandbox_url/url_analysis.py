import json
import sys
import os
import re
import socket
import time
from datetime import datetime

try:
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout
    PLAYWRIGHT_OK = True
except ImportError:
    PLAYWRIGHT_OK = False

TARGET = os.environ.get("TARGET_URL", "")
OUTPUT = "/results/url_behavior.json"

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "account", "update", "secure",
    "banking", "paypal", "amazon", "microsoft", "apple", "google",
    "password", "credential", "confirm", "wallet", "crypto"
]

SUSPICIOUS_EXTENSIONS = [
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar",
    ".zip", ".rar", ".iso", ".img", ".dmg", ".msi"
]

def analyze_url(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result = {
        "status": "completed",
        "target_url": url,
        "final_url": url,
        "page_title": "",
        "http_requests": [],
        "redirects": [],
        "scripts_loaded": [],
        "cookies": [],
        "forms": [],
        "downloads_attempted": [],
        "suspicious_indicators": [],
        "network_domains": [],
        "console_errors": [],
        "page_text_sample": "",
        "screenshot_path": "",
        "threat_score": 0,
        "threat_level": "CLEAN",
        "mitre_tags": [],
        "duration_seconds": 0
    }

    if not PLAYWRIGHT_OK:
        result["status"] = "error"
        result["error"] = "Playwright not available"
        return result

    start = time.time()
    requests_log = []
    redirects_log = []
    console_log = []
    domains_seen = set()

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-extensions",
                ]
            )

            context = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
                viewport={"width": 1280, "height": 720},
                ignore_https_errors=True,
            )

            page = context.new_page()

            # Track all network requests
            def on_request(req):
                try:
                    req_url = req.url
                    requests_log.append({
                        "url": req_url[:200],
                        "method": req.method,
                        "resource_type": req.resource_type,
                    })
                    # Extract domain
                    m = re.search(r'https?://([^/]+)', req_url)
                    if m:
                        domains_seen.add(m.group(1).split(":")[0])

                    # Check for suspicious file downloads
                    for ext in SUSPICIOUS_EXTENSIONS:
                        if req_url.lower().endswith(ext):
                            result["downloads_attempted"].append(req_url[:200])
                except Exception:
                    pass

            # Track redirects
            def on_response(resp):
                try:
                    status = resp.status
                    if status in (301, 302, 303, 307, 308):
                        redirects_log.append({
                            "from": resp.url[:200],
                            "status": status,
                        })
                except Exception:
                    pass

            # Track console errors
            page.on("console", lambda msg: console_log.append(msg.text[:200]) if msg.type == "error" else None)
            page.on("request", on_request)
            page.on("response", on_response)

            # Navigate with 30s timeout
            try:
                response = page.goto(url, timeout=30000, wait_until="networkidle")
                result["final_url"] = page.url
                result["http_status"] = response.status if response else 0
            except PlaywrightTimeout:
                result["suspicious_indicators"].append("Page load timeout — possible evasion technique")
            except Exception as e:
                result["suspicious_indicators"].append(f"Navigation error: {str(e)[:100]}")

            # Wait a bit for JS to execute
            page.wait_for_timeout(3000)

            # Page title
            try:
                result["page_title"] = page.title()[:200]
            except Exception:
                pass

            # Extract all scripts loaded
            try:
                scripts = page.eval_on_selector_all("script[src]", "els => els.map(e => e.src)")
                result["scripts_loaded"] = [s[:200] for s in scripts[:20]]
            except Exception:
                pass

            # Extract forms (phishing indicator)
            try:
                forms = page.eval_on_selector_all("form", """els => els.map(e => ({
                    action: e.action,
                    method: e.method,
                    inputs: Array.from(e.querySelectorAll('input')).map(i => ({type: i.type, name: i.name}))
                }))""")
                result["forms"] = forms[:5]
            except Exception:
                pass

            # Cookies
            try:
                cookies = context.cookies()
                result["cookies"] = [{"name": c["name"], "domain": c["domain"], "secure": c["secure"]} for c in cookies[:10]]
            except Exception:
                pass

            # Page text sample (for keyword detection)
            try:
                text = page.inner_text("body")
                result["page_text_sample"] = text[:500]
            except Exception:
                pass

            # Screenshot
            try:
                screenshot_path = "/results/screenshot.png"
                page.screenshot(path=screenshot_path, full_page=False)
                result["screenshot_path"] = screenshot_path
            except Exception:
                pass

            browser.close()

    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)[:200]

    # ── Populate results ──────────────────────────────────────────────────
    result["http_requests"] = requests_log[:50]
    result["redirects"] = redirects_log[:10]
    result["console_errors"] = console_log[:10]
    result["network_domains"] = sorted(list(domains_seen))[:30]
    result["duration_seconds"] = round(time.time() - start)

    # ── Risk scoring ──────────────────────────────────────────────────────
    score = 0
    flags = result["suspicious_indicators"]
    mitre = []

    # Redirects
    if len(redirects_log) >= 3:
        score += 20
        flags.append(f"Multiple redirects detected ({len(redirects_log)}) — possible redirect chain attack")
        mitre.append({"id": "T1659", "name": "Content Injection"})

    # Suspicious downloads
    if result["downloads_attempted"]:
        score += 35
        flags.append(f"File download attempted: {result['downloads_attempted'][0][:80]}")
        mitre.append({"id": "T1105", "name": "Ingress Tool Transfer"})

    # Forms on page (phishing)
    if result["forms"]:
        score += 15
        flags.append(f"{len(result['forms'])} form(s) detected on page — possible credential harvesting")
        mitre.append({"id": "T1056.003", "name": "Web Portal Capture"})

        # Check for password fields
        for form in result["forms"]:
            inputs = form.get("inputs", [])
            if any(i.get("type") == "password" for i in inputs):
                score += 20
                flags.append("Password input field detected — high phishing risk")
                break

    # Many external domains contacted
    if len(domains_seen) > 10:
        score += 10
        flags.append(f"Contacted {len(domains_seen)} external domains — possible tracking/malvertising")

    # Suspicious keywords in page text
    page_text_lower = result["page_text_sample"].lower()
    kw_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in page_text_lower]
    if len(kw_hits) >= 3:
        score += 15
        flags.append(f"Suspicious keywords detected: {', '.join(kw_hits[:5])}")
        mitre.append({"id": "T1598.003", "name": "Spearphishing Link"})

    # URL changed after load (redirect to different domain)
    original_domain = re.search(r'https?://([^/]+)', url)
    final_domain = re.search(r'https?://([^/]+)', result["final_url"])
    if original_domain and final_domain and original_domain.group(1) != final_domain.group(1):
        score += 25
        flags.append(f"Domain changed after load: {original_domain.group(1)} → {final_domain.group(1)}")
        mitre.append({"id": "T1036.005", "name": "Match Legitimate Name or Location"})

    # Console errors (obfuscated JS)
    if len(console_log) > 5:
        score += 10
        flags.append(f"{len(console_log)} console errors — possible obfuscated JavaScript")

    score = min(score, 100)
    result["threat_score"] = score
    result["threat_level"] = "HIGH" if score >= 70 else "MEDIUM" if score >= 40 else "LOW" if score >= 15 else "CLEAN"
    result["mitre_tags"] = mitre

    return result


if __name__ == "__main__":
    if not TARGET:
        print(json.dumps({"status": "error", "error": "No TARGET_URL set"}))
        sys.exit(1)

    os.makedirs("/results", exist_ok=True)
    result = analyze_url(TARGET)

    with open(OUTPUT, "w") as f:
        json.dump(result, f, indent=2)

    print(json.dumps(result, indent=2))