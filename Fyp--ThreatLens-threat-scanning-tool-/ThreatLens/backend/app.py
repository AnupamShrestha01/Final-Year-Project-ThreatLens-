"""
backend/app.py — ThreatLens Flask Application Entry Point
Run: python backend/app.py
API runs on http://127.0.0.1:5000
"""
import sys, os

# Make project root importable
ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)

# ── Load API keys from .env file ──────────────────────────────────────────
_env_path = os.path.join(ROOT, ".env", ".env")
if os.path.exists(_env_path):
    with open(_env_path) as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _v = _line.split("=", 1)
                os.environ.setdefault(_k.strip(), _v.strip())

from flask import Flask, jsonify
from flask.wrappers import Response

# ── App init ──────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = "threatlens-secret-key-change-in-production"

# ── Manual CORS (no flask-cors needed) ────────────────────────────────────
@app.after_request
def add_cors(response: Response) -> Response:
    response.headers["Access-Control-Allow-Origin"]  = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS, DELETE"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, x-apikey, X-User-ID"
    return response

@app.route("/<path:path>", methods=["OPTIONS"])
def handle_options(path):
    return jsonify({}), 200

# ── Import & register Blueprints ──────────────────────────────────────────
from routes.auth_routes import auth_bp
from routes.scan_routes import scan_bp
from routes.chat_routes import chat_bp
from routes.profile_routes import profile_bp
from routes.admin_routes import admin_bp

app.register_blueprint(auth_bp, url_prefix="/api/auth")
app.register_blueprint(scan_bp, url_prefix="/api/scan")
app.register_blueprint(chat_bp, url_prefix="/api/chat")
app.register_blueprint(profile_bp, url_prefix="/profile")
app.register_blueprint(admin_bp, url_prefix="/admin")


# ── Health check ──────────────────────────────────────────────────────────
@app.route("/")
def home():
    return jsonify({
        "status": "ThreatLens backend running",
        "version": "2.0",
        "endpoints": {
            "register":  "POST /api/auth/register",
            "login":     "POST /api/auth/login",
            "scan_file": "POST /api/scan/file",
            "scan_url":  "POST /api/scan/url",
            "scan_hash": "POST /api/scan/hash",
            "history":   "GET  /api/scan/history/<user_id>",
            "chat":      "POST /api/chat/ask"
        }
    })

# ── DB init + run ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    sys.path.insert(0, ROOT)
    from database.db import init_db
    print("[*] Initializing database...")
    init_db()
    from backend.threat_intel.community_intel import ensure_community_table
    ensure_community_table()
    print("[*] ThreatLens backend starting on http://127.0.0.1:5000")
    app.run(debug=True, host="127.0.0.1", port=5000)