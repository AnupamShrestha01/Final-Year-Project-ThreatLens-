"""
backend/services/url_behavior_service.py
URL Behavior Analysis using Playwright headless browser in Docker sandbox.
"""
import subprocess
import tempfile
import shutil
import json
import os
import uuid

SANDBOX_IMAGE = "threatlens-url-sandbox"

def run_url_behavior(target_url: str) -> dict:
    """
    Visits a URL inside isolated Docker container using headless Chromium.
    Captures HTTP requests, redirects, scripts, forms, cookies, screenshots.
    """
    scan_id = str(uuid.uuid4())[:8]
    temp_results_dir = tempfile.mkdtemp(prefix=f"tl_url_{scan_id}_")

    try:
        docker_cmd = [
            "docker", "run", "--rm",
            "--memory", "512m",
            "--cpus", "1.0",
            "-e", f"TARGET_URL={target_url}",
            "-v", f"{temp_results_dir}:/results",
            SANDBOX_IMAGE
        ]

        result = subprocess.run(
            docker_cmd,
            capture_output=True,
            text=True,
            timeout=120
        )

        # Read behavior JSON from results folder
        behavior_json_path = os.path.join(temp_results_dir, "url_behavior.json")

        if os.path.exists(behavior_json_path):
            with open(behavior_json_path, "r") as f:
                behavior_data = json.load(f)

            # Attach screenshot as base64 if exists
            screenshot_path = os.path.join(temp_results_dir, "screenshot.png")
            if os.path.exists(screenshot_path):
                import base64
                with open(screenshot_path, "rb") as img:
                    behavior_data["screenshot_b64"] = base64.b64encode(img.read()).decode("utf-8")

            return {"success": True, "data": behavior_data}

        else:
            # Try parsing stdout directly
            try:
                parsed = json.loads(result.stdout)
                return {"success": True, "data": parsed}
            except Exception:
                return {"success": False, "data": _error_result("No output from URL sandbox")}

    except subprocess.TimeoutExpired:
        return {"success": False, "data": _error_result("URL sandbox timeout — page took too long")}
    except Exception as e:
        return {"success": False, "data": _error_result(f"URL behavior analysis failed: {str(e)}")}
    finally:
        shutil.rmtree(temp_results_dir, ignore_errors=True)


def _error_result(message: str) -> dict:
    return {
        "status": "error",
        "error_message": message,
        "http_requests": [],
        "redirects": [],
        "scripts_loaded": [],
        "cookies": [],
        "forms": [],
        "suspicious_indicators": [],
        "network_domains": [],
        "mitre_tags": [],
        "threat_score": 0,
        "threat_level": "UNKNOWN"
    }