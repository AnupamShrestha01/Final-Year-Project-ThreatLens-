"""
backend/routes/scan_routes.py
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))

import json
import tempfile
from flask import Blueprint, request, jsonify
from database.db import get_db

scan_bp = Blueprint("scan", __name__)


# ── File Scan ──────────────────────────────────────────────────────────────
@scan_bp.route("/file", methods=["POST"])
def scan_file():
    from backend.services.file_service import scan_file as do_scan

    file = request.files.get("file")
    if not file:
        return jsonify({"success": False, "message": "No file uploaded."}), 400

    filename  = file.filename or "unknown"
    file_data = file.read()

    if len(file_data) > 32 * 1024 * 1024:
        return jsonify({"success": False, "message": "File too large (max 32MB)."}), 413

    try:
        result = do_scan(file_data, filename)
    except Exception as e:
        return jsonify({"success": False, "message": f"Scan error: {str(e)}"}), 500

    user_id = request.form.get("user_id")
    if user_id:
        try:
            db = get_db()
            db.execute(
                """INSERT INTO scan_history
                   (user_id, scan_type, target, filename, file_size, verdict, risk_level,
                    threat_score, sha256, md5, result_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    int(user_id), "file",
                    result.get("filename"),
                    result.get("filename"),
                    result.get("file_size"),
                    result.get("verdict"),
                    result.get("risk"),
                    result.get("threat_score"),
                    result.get("hashes", {}).get("sha256"),
                    result.get("hashes", {}).get("md5"),
                    json.dumps(result)
                )
            )
            db.commit()
            db.close()
        except Exception:
            pass

    return jsonify({"success": True, "result": result})


# ── URL / Domain / IP Scan ─────────────────────────────────────────────────
@scan_bp.route("/url", methods=["POST"])
def scan_url():
    if request.is_json:
        body    = request.get_json() or {}
        value   = body.get("value", "").strip()
        user_id = body.get("user_id")
    else:
        value   = (request.form.get("value") or "").strip()
        user_id = request.form.get("user_id")

    if not value:
        return jsonify({"success": False, "message": "No URL/domain/IP provided."}), 400

    try:
        from backend.services.url_service import scan_url as do_scan
        result = do_scan(value, user_id=int(user_id) if user_id else None)
    except Exception as e:
        return jsonify({"success": False, "message": f"Scan error: {str(e)}"}), 500

    if user_id:
        try:
            db = get_db()
            db.execute(
                """INSERT INTO scan_history
                   (user_id, scan_type, target, verdict, risk_level, threat_score, result_json)
                   VALUES (?,?,?,?,?,?,?)""",
                (
                    int(user_id), "url",
                    result.get("input", value),
                    result.get("verdict", "Clean"),
                    result.get("risk", "Low"),
                    result.get("threat_score", 0),
                    json.dumps(result)
                )
            )
            db.commit()
            db.close()
        except Exception:
            pass

    return jsonify({"success": True, "result": result})


# ── Hash Scan ──────────────────────────────────────────────────────────────
@scan_bp.route("/hash", methods=["POST"])
def scan_hash():
    if request.is_json:
        body     = request.get_json() or {}
        hash_val = body.get("hash", "").strip()
        user_id  = body.get("user_id")
    else:
        hash_val = (request.form.get("hash") or "").strip()
        user_id  = request.form.get("user_id")

    if not hash_val:
        return jsonify({"success": False, "message": "No hash provided."}), 400

    try:
        from backend.services.hash_service import scan_hash as do_scan
        result = do_scan(hash_val, user_id=int(user_id) if user_id else None)
    except Exception as e:
        return jsonify({"success": False, "message": f"Scan error: {str(e)}"}), 500

    if user_id and result.get("verdict") not in ("Invalid", None):
        try:
            db = get_db()
            db.execute(
                """INSERT INTO scan_history
                   (user_id, scan_type, target, verdict, risk_level, threat_score, sha256, result_json)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    int(user_id), "hash",
                    result.get("input"),
                    result.get("verdict", "Clean"),
                    result.get("risk", "Low"),
                    result.get("threat_score", 0),
                    result.get("input") if len(hash_val) == 64 else None,
                    json.dumps(result)
                )
            )
            db.commit()
            db.close()
        except Exception:
            pass

    return jsonify({"success": True, "result": result})


# ── Behavior Analysis ──────────────────────────────────────────────────────
@scan_bp.route("/behavior", methods=["POST"])
def scan_behavior():
    file = request.files.get("file")
    if not file:
        return jsonify({"success": False, "message": "No file uploaded."}), 400

    filename  = file.filename or "unknown"
    file_data = file.read()

    if len(file_data) > 32 * 1024 * 1024:
        return jsonify({"success": False, "message": "File too large (max 32MB)."}), 413

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix="_" + filename)
    tmp.write(file_data)
    tmp.close()

    try:
        from backend.services.behavior_service import run_behavior_analysis
        analysis = run_behavior_analysis(tmp.name, filename)
    except Exception as e:
        return jsonify({"success": False, "message": f"Behavior analysis error: {str(e)}"}), 500
    finally:
        try:
            os.unlink(tmp.name)
        except Exception:
            pass

    return jsonify({
        "success": True,
        "result": analysis.get("data", {}),
        "filename": filename
    })
# ── Recon Analysis (IP / Domain / URL) ────────────────────────────────────
@scan_bp.route("/recon", methods=["POST"])
def scan_recon():
    if request.is_json:
        body   = request.get_json() or {}
        target = body.get("target", "").strip()
    else:
        target = (request.form.get("target") or "").strip()

    if not target:
        return jsonify({"success": False, "message": "No target provided."}), 400

    try:
        from backend.services.recon_service import run_recon
        result = run_recon(target)
    except Exception as e:
        return jsonify({"success": False, "message": f"Recon error: {str(e)}"}), 500

    return jsonify({"success": True, "result": result})
# ── URL Behavior Analysis ──────────────────────────────────────────────────
@scan_bp.route("/url-behavior", methods=["POST"])
def scan_url_behavior():
    if request.is_json:
        body   = request.get_json() or {}
        target = body.get("target", "").strip()
    else:
        target = (request.form.get("target") or "").strip()

    if not target:
        return jsonify({"success": False, "message": "No URL provided."}), 400

    try:
        from backend.services.url_behavior_service import run_url_behavior
        result = run_url_behavior(target)
    except Exception as e:
        return jsonify({"success": False, "message": f"URL behavior error: {str(e)}"}), 500

    return jsonify({
        "success": True,
        "result": result.get("data", {}),
        "target": target
    })

# ── Scan History ──────────────────────────────────────────────────────────
@scan_bp.route("/history/<int:user_id>", methods=["GET"])
def get_history(user_id):
    try:
        db   = get_db()
        rows = db.execute(
            """SELECT id, scan_type, filename, target, verdict, risk_level,
                      threat_score, sha256, scanned_at
               FROM scan_history
               WHERE user_id = ?
               ORDER BY scanned_at DESC LIMIT 50""",
            (user_id,)
        ).fetchall()
        db.close()
        return jsonify({"success": True, "history": [dict(r) for r in rows]})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


# ── Dashboard Stats ────────────────────────────────────────────────────────
@scan_bp.route("/stats/<int:user_id>", methods=["GET"])
def get_user_stats(user_id):
    try:
        db = get_db()
        total      = db.execute("SELECT COUNT(*) FROM scan_history WHERE user_id=?", (user_id,)).fetchone()[0]
        malicious  = db.execute("SELECT COUNT(*) FROM scan_history WHERE user_id=? AND verdict='Malicious'",  (user_id,)).fetchone()[0]
        suspicious = db.execute("SELECT COUNT(*) FROM scan_history WHERE user_id=? AND verdict='Suspicious'", (user_id,)).fetchone()[0]
        clean      = db.execute("SELECT COUNT(*) FROM scan_history WHERE user_id=? AND verdict='Clean'",      (user_id,)).fetchone()[0]
        file_scans = db.execute("SELECT COUNT(*) FROM scan_history WHERE user_id=? AND scan_type='file'", (user_id,)).fetchone()[0]
        url_scans  = db.execute("SELECT COUNT(*) FROM scan_history WHERE user_id=? AND scan_type='url'",  (user_id,)).fetchone()[0]
        hash_scans = db.execute("SELECT COUNT(*) FROM scan_history WHERE user_id=? AND scan_type='hash'", (user_id,)).fetchone()[0]
        last_row   = db.execute("SELECT scanned_at FROM scan_history WHERE user_id=? ORDER BY scanned_at DESC LIMIT 1", (user_id,)).fetchone()
        last_scan  = last_row[0] if last_row else None
        avg_row    = db.execute("SELECT AVG(threat_score) FROM scan_history WHERE user_id=?", (user_id,)).fetchone()
        avg_score  = round(avg_row[0] or 0, 1)
        recent = db.execute(
            """SELECT scan_type, filename, target, verdict, threat_score, scanned_at
               FROM scan_history WHERE user_id=?
               ORDER BY scanned_at DESC LIMIT 5""",
            (user_id,)
        ).fetchall()
        db.close()
        return jsonify({
            "success":        True,
            "total":          total,
            "malicious":      malicious,
            "suspicious":     suspicious,
            "clean":          clean,
            "file_scans":     file_scans,
            "url_scans":      url_scans,
            "hash_scans":     hash_scans,
            "last_scan":      last_scan,
            "avg_score":      avg_score,
            "detection_rate": round((malicious / total * 100), 1) if total > 0 else 0,
            "recent":         [dict(r) for r in recent],
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


# ── MalwareBazaar DB ──────────────────────────────────────────────────────
@scan_bp.route("/mb/import", methods=["POST"])
def import_malware_feeds():
    try:
        from backend.threat_intel.malwarebazaar import import_all_feeds
        return jsonify(import_all_feeds())
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@scan_bp.route("/mb/stats", methods=["GET"])
def malware_db_stats():
    try:
        from backend.threat_intel.malwarebazaar import get_db_stats
        return jsonify({"success": True, **get_db_stats()})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


# ── URLhaus DB ────────────────────────────────────────────────────────────
@scan_bp.route("/urldb/import", methods=["POST"])
def import_url_feeds():
    try:
        from backend.threat_intel.url_db import import_url_feeds
        return jsonify(import_url_feeds())
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@scan_bp.route("/urldb/stats", methods=["GET"])
def url_db_stats():
    try:
        from backend.threat_intel.url_db import get_url_db_stats
        return jsonify({"success": True, **get_url_db_stats()})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500
# ── Delete single scan from history ──────────────────────────────────────
@scan_bp.route("/history/delete/<int:scan_id>", methods=["DELETE"])
def delete_scan(scan_id):
    from flask import session, request
    # Get user_id same way as profile
    user_id = session.get("user_id")
    if not user_id:
        user_id = request.headers.get("X-User-ID")
    if not user_id:
        return jsonify({"error": "Not logged in"}), 401

    from database.db import get_db
    db = get_db()
    db.execute(
        "DELETE FROM scan_history WHERE id = ? AND user_id = ?",
        (scan_id, int(user_id))
    )
    db.commit()
    db.close()
    return jsonify({"success": True})