from flask import Blueprint, jsonify, request, session
import os, sys

admin_bp = Blueprint("admin", __name__)

# ── Use same db helper as rest of project ─────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from database.db import get_db

def get_uid():
    uid = session.get("user_id")
    if uid: return int(uid)
    uid = request.headers.get("X-User-ID")
    if uid: return int(uid)
    return None

def is_admin():
    uid = get_uid()
    if not uid: return False
    conn = get_db()
    row  = conn.execute("SELECT role FROM users WHERE id = ?", (uid,)).fetchone()
    conn.close()
    return row and row["role"] == "admin"


# ── GET /admin/stats ──────────────────────────────────────────────────────
@admin_bp.route("/stats", methods=["GET"])
def get_stats():
    if not is_admin():
        return jsonify({"error": "Access denied"}), 403

    conn   = get_db()
    cursor = conn.cursor()

    # User stats
    cursor.execute("SELECT COUNT(*) AS total FROM users")
    total_users = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM users WHERE role = 'admin'")
    total_admins = cursor.fetchone()["total"]

    # Scan stats
    cursor.execute("SELECT COUNT(*) AS total FROM scan_history")
    total_scans = cursor.fetchone()["total"]

    cursor.execute("""
        SELECT
            SUM(CASE WHEN scan_type='file' THEN 1 ELSE 0 END) AS file_scans,
            SUM(CASE WHEN scan_type='url'  THEN 1 ELSE 0 END) AS url_scans,
            SUM(CASE WHEN scan_type='hash' THEN 1 ELSE 0 END) AS hash_scans,
            SUM(CASE WHEN verdict='Malicious'  THEN 1 ELSE 0 END) AS malicious,
            SUM(CASE WHEN verdict='Suspicious' THEN 1 ELSE 0 END) AS suspicious,
            SUM(CASE WHEN verdict='Clean'      THEN 1 ELSE 0 END) AS clean,
            AVG(threat_score) AS avg_score
        FROM scan_history
    """)
    scan_stats = dict(cursor.fetchone())

    # Recent signups
    cursor.execute("""
        SELECT id, name, email, role, created_at
        FROM users ORDER BY created_at DESC LIMIT 5
    """)
    recent_users = [dict(r) for r in cursor.fetchall()]

    # Malware hash DB stats
    cursor.execute("SELECT COUNT(*) AS total FROM malware_hashes")
    malware_hashes = cursor.fetchone()["total"]

    # URL blacklist stats
    cursor.execute("SELECT COUNT(*) AS total FROM url_blacklist")
    url_blacklist = cursor.fetchone()["total"]

    # Top threats
    cursor.execute("""
        SELECT target, verdict, threat_score, scan_type, scanned_at
        FROM scan_history
        WHERE verdict = 'Malicious'
        ORDER BY threat_score DESC
        LIMIT 5
    """)
    top_threats = [dict(r) for r in cursor.fetchall()]

    conn.close()

    return jsonify({
        "users": {
            "total":  total_users,
            "admins": total_admins,
            "recent": recent_users
        },
        "scans": {
            **scan_stats,
            "total": total_scans,
            "avg_score": round(float(scan_stats.get("avg_score") or 0), 1)
        },
        "community_db": {
            "malware_hashes": malware_hashes,
            "url_blacklist":  url_blacklist
        },
        "top_threats": top_threats
    })


# ── GET /admin/users ──────────────────────────────────────────────────────
@admin_bp.route("/users", methods=["GET"])
def get_users():
    if not is_admin():
        return jsonify({"error": "Access denied"}), 403

    conn   = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT
            u.id, u.name, u.email, u.role, u.created_at,
            COUNT(s.id)                                           AS total_scans,
            SUM(CASE WHEN s.verdict='Malicious' THEN 1 ELSE 0 END) AS malicious_scans,
            MAX(s.scanned_at)                                     AS last_scan
        FROM users u
        LEFT JOIN scan_history s ON u.id = s.user_id
        GROUP BY u.id
        ORDER BY u.created_at DESC
    """)
    users = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify({"users": users})


# ── GET /admin/scans ──────────────────────────────────────────────────────
@admin_bp.route("/scans", methods=["GET"])
def get_all_scans():
    if not is_admin():
        return jsonify({"error": "Access denied"}), 403

    limit  = int(request.args.get("limit",  100))
    offset = int(request.args.get("offset", 0))

    conn   = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT
            s.id, s.scan_type, s.target, s.filename,
            s.verdict, s.threat_score, s.risk_level, s.scanned_at,
            u.name AS user_name, u.email AS user_email
        FROM scan_history s
        LEFT JOIN users u ON s.user_id = u.id
        ORDER BY s.scanned_at DESC
        LIMIT ? OFFSET ?
    """, (limit, offset))
    scans = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT COUNT(*) AS total FROM scan_history")
    total = cursor.fetchone()["total"]
    conn.close()

    return jsonify({"scans": scans, "total": total})


# ── POST /admin/users/role ────────────────────────────────────────────────
@admin_bp.route("/users/role", methods=["POST"])
def change_role():
    if not is_admin():
        return jsonify({"error": "Access denied"}), 403

    data    = request.get_json(silent=True) or {}
    user_id = data.get("user_id")
    role    = data.get("role")

    if not user_id or role not in ("admin", "user"):
        return jsonify({"error": "Invalid request"}), 400

    conn = get_db()
    conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
    conn.commit()
    conn.close()
    return jsonify({"success": True})


# ── DELETE /admin/users/<id> ──────────────────────────────────────────────
@admin_bp.route("/users/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):
    if not is_admin():
        return jsonify({"error": "Access denied"}), 403

    conn = get_db()
    conn.execute("DELETE FROM scan_history WHERE user_id = ?", (user_id,))
    conn.execute("DELETE FROM users WHERE id = ?",             (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})


# ── DELETE /admin/scans/<id> ──────────────────────────────────────────────
@admin_bp.route("/scans/<int:scan_id>", methods=["DELETE"])
def delete_scan(scan_id):
    if not is_admin():
        return jsonify({"error": "Access denied"}), 403

    conn = get_db()
    conn.execute("DELETE FROM scan_history WHERE id = ?", (scan_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})