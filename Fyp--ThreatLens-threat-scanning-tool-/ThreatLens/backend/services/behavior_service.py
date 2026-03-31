import subprocess
import tempfile
import shutil
import json
import os
import uuid

# Path to your sandbox folder
SANDBOX_PATH = r"C:\Users\nitro\Downloads\ThreatLens_Working\sandbox"
DOCKER_IMAGE = "threatlens-sandbox"

def run_behavior_analysis(file_path: str, filename: str) -> dict:
    """
    Runs a file inside the Docker sandbox and returns behavior report.
    """
    # Create unique temp folders for this scan
    scan_id = str(uuid.uuid4())[:8]
    temp_sample_dir = tempfile.mkdtemp(prefix=f"tl_sample_{scan_id}_")
    temp_results_dir = tempfile.mkdtemp(prefix=f"tl_results_{scan_id}_")

    try:
        # Copy uploaded file into temp sample folder
        dest_path = os.path.join(temp_sample_dir, filename)
        shutil.copy2(file_path, dest_path)

        # Build docker command
        docker_cmd = [
            "docker", "run", "--rm",
            "--network", "none",          # No internet access
            "--memory", "512m",           # Limit RAM
            "--cpus", "1.0",              # Limit CPU
            "-v", f"{temp_sample_dir}:/sample",
            "-v", f"{temp_results_dir}:/results",
            DOCKER_IMAGE
        ]

        # Run the container with 90 second timeout
        result = subprocess.run(
            docker_cmd,
            capture_output=True,
            text=True,
            timeout=90
        )

        # Read behavior.json from results folder
        behavior_json_path = os.path.join(temp_results_dir, "behavior.json")

        if os.path.exists(behavior_json_path):
            with open(behavior_json_path, "r") as f:
                behavior_data = json.load(f)
            return {
                "success": True,
                "data": behavior_data
            }
        else:
            # If no JSON file, return stdout as fallback
            return {
                "success": True,
                "data": json.loads(result.stdout) if result.stdout else _error_result("No output from sandbox")
            }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "data": _error_result("Sandbox timeout — file took too long to analyze")
        }
    except subprocess.CalledProcessError as e:
        return {
            "success": False,
            "data": _error_result(f"Docker error: {str(e)}")
        }
    except Exception as e:
        return {
            "success": False,
            "data": _error_result(f"Behavior analysis failed: {str(e)}")
        }
    finally:
        # Always clean up temp folders
        shutil.rmtree(temp_sample_dir, ignore_errors=True)
        shutil.rmtree(temp_results_dir, ignore_errors=True)


def _error_result(message: str) -> dict:
    return {
        "status": "error",
        "error_message": message,
        "syscall_summary": {},
        "suspicious_indicators": [],
        "mitre_tags": [],
        "threat_score": 0,
        "threat_level": "UNKNOWN"
    }