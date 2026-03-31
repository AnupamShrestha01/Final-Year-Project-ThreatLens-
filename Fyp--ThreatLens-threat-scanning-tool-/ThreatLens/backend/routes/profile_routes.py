from flask import Blueprint, jsonify, session, request
import os, json, secrets

profile_bp = Blueprint("profile", __name__)

# ── Use the SAME db helper as the rest of the project ─────────────────────
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from database.db import get_db

def get_current_user_id():
    uid = session.get("user_id")
    if uid: return int(uid)
    uid = request.headers.get("X-User-ID")
    if uid: return int(uid)
    if request.is_json:
        body = request.get_json(silent=True) or {}
        uid  = body.get("user_id")
        if uid: return int(uid)
    return None

# ── GET /profile/me ───────────────────────────────────────────────────────
@profile_bp.route("/me", methods=["GET"])
def get_profile():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "Not logged in"}), 401

    conn   = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT id, name, email, created_at FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    cursor.execute("""
        SELECT
            COUNT(*)                                           AS total_scans,
            SUM(CASE WHEN scan_type='file' THEN 1 ELSE 0 END) AS file_scans,
            SUM(CASE WHEN scan_type='url'  THEN 1 ELSE 0 END) AS url_scans,
            SUM(CASE WHEN scan_type='hash' THEN 1 ELSE 0 END) AS hash_scans,
            MAX(scanned_at)                                    AS last_scan
        FROM scan_history WHERE user_id = ?
    """, (user_id,))
    usage = dict(cursor.fetchone())

    cursor.execute("""
        SELECT
            SUM(CASE WHEN verdict='Malicious'  THEN 1 ELSE 0 END) AS malicious,
            SUM(CASE WHEN verdict='Suspicious' THEN 1 ELSE 0 END) AS suspicious,
            SUM(CASE WHEN verdict='Clean'      THEN 1 ELSE 0 END) AS clean,
            AVG(threat_score)                                      AS avg_score,
            COUNT(*)                                               AS total
        FROM scan_history WHERE user_id = ?
    """, (user_id,))
    analytics = dict(cursor.fetchone())

    total          = analytics.get("total") or 1
    threats        = (analytics.get("malicious") or 0) + (analytics.get("suspicious") or 0)
    detection_rate = round((threats / total) * 100, 1) if total > 0 else 0

    cursor.execute("""
        SELECT scan_type, target, filename, verdict, threat_score, risk_level, scanned_at
        FROM scan_history
        WHERE user_id = ?
        ORDER BY scanned_at DESC
        LIMIT 10
    """, (user_id,))
    recent = [dict(r) for r in cursor.fetchall()]

    cursor.execute("""
        SELECT
            SUM(CASE WHEN verdict='Malicious'  THEN 1 ELSE 0 END) AS malicious_reports,
            SUM(CASE WHEN verdict='Suspicious' THEN 1 ELSE 0 END) AS suspicious_reports,
            COUNT(*) AS total_contributions
        FROM scan_history WHERE user_id = ?
    """, (user_id,))
    community = dict(cursor.fetchone())

    # API key
    try:
        cursor.execute("SELECT api_key FROM users WHERE id = ?", (user_id,))
        row     = cursor.fetchone()
        api_key = row["api_key"] if row and "api_key" in row.keys() else None
    except Exception:
        api_key = None

    conn.close()

    return jsonify({
        "user": {
            "id":           user["id"],
            "name":         user["name"],
            "email":        user["email"],
            "role":         session.get("role", "user"),
            "member_since": user["created_at"],
            "account_type": "Free"
        },
        "usage":     usage,
        "analytics": {
            **analytics,
            "detection_rate": detection_rate,
            "avg_score":      round(float(analytics.get("avg_score") or 0), 1)
        },
        "recent_activity": recent,
        "community":       community,
        "api_key":         api_key
    })


# ── POST /profile/settings/update ────────────────────────────────────────
@profile_bp.route("/settings/update", methods=["POST"])
def update_settings():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "Not logged in"}), 401

    data   = request.get_json(silent=True) or {}
    conn   = get_db()
    cursor = conn.cursor()

    if data.get("email"):
        cursor.execute("UPDATE users SET email = ? WHERE id = ?", (data["email"], user_id))
    if data.get("name"):
        cursor.execute("UPDATE users SET name = ? WHERE id = ?", (data["name"], user_id))
    if data.get("new_password"):
        import hashlib
        hashed = hashlib.sha256(data["new_password"].encode()).hexdigest()
        cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hashed, user_id))

    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "Settings updated successfully"})


# ── POST /profile/api-key/generate ───────────────────────────────────────
@profile_bp.route("/api-key/generate", methods=["POST"])
def generate_api_key():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "Not logged in"}), 401

    new_key = "tl_" + secrets.token_hex(24)
    conn    = get_db()
    try:
        conn.execute("ALTER TABLE users ADD COLUMN api_key TEXT")
        conn.commit()
    except Exception:
        pass
    conn.execute("UPDATE users SET api_key = ? WHERE id = ?", (new_key, user_id))
    conn.commit()
    conn.close()
    return jsonify({"success": True, "api_key": new_key})


# ── POST /profile/api-key/revoke ─────────────────────────────────────────
@profile_bp.route("/api-key/revoke", methods=["POST"])
def revoke_api_key():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "Not logged in"}), 401

    conn = get_db()
    conn.execute("UPDATE users SET api_key = NULL WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})


# ── GET /profile/export-history ───────────────────────────────────────────
@profile_bp.route("/export-history", methods=["GET"])
def export_history():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "Not logged in"}), 401

    conn   = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT scan_type, target, filename, verdict, threat_score, risk_level, scanned_at
        FROM scan_history WHERE user_id = ?
        ORDER BY scanned_at DESC
    """, (user_id,))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify({"success": True, "data": rows, "count": len(rows)})


# ── POST /profile/clear-history ───────────────────────────────────────────
@profile_bp.route("/clear-history", methods=["POST"])
def clear_history():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "Not logged in"}), 401

    conn = get_db()
    conn.execute("DELETE FROM scan_history WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})


# ── POST /profile/delete-account ──────────────────────────────────────────
@profile_bp.route("/delete-account", methods=["POST"])
def delete_account():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "Not logged in"}), 401

    conn = get_db()
    conn.execute("DELETE FROM scan_history WHERE user_id = ?", (user_id,))
    conn.execute("DELETE FROM users WHERE id = ?",             (user_id,))
    conn.commit()
    conn.close()
    session.clear()
    return jsonify({"success": True})


# ── POST /profile/logout ──────────────────────────────────────────────────
@profile_bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"success": True})