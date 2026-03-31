"""
backend/routes/auth_routes.py
Auth routes: /api/auth/register  /api/auth/login  /api/auth/logout
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))

from flask import Blueprint, request, jsonify, session
import hashlib
from database.db import get_db, init_db

auth_bp = Blueprint("auth", __name__)

# ──────────────────────────────────────────────
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


# ──────────────────────────────────────────────
@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or request.form
    name     = (data.get("name") or "").strip()
    email    = (data.get("email") or "").strip().lower()
    password = (data.get("password") or "").strip()

    if not name or not email or not password:
        return jsonify({"success": False, "message": "All fields are required."}), 400

    if len(password) < 6:
        return jsonify({"success": False, "message": "Password must be at least 6 characters."}), 400

    db = get_db()
    try:
        existing = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if existing:
            return jsonify({"success": False, "message": "Email already registered."}), 409

        db.execute(
            "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
            (name, email, hash_password(password))
        )
        db.commit()
        user = db.execute("SELECT id, name, email FROM users WHERE email = ?", (email,)).fetchone()
        return jsonify({
            "success": True,
            "message": "Account created successfully.",
            "user": {"id": user["id"], "name": user["name"], "email": user["email"]}
        }), 201
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        db.close()


# ──────────────────────────────────────────────
@auth_bp.route("/login", methods=["POST"])
def login():
    data     = request.get_json(silent=True) or request.form
    email    = (data.get("email") or "").strip().lower()
    password = (data.get("password") or "").strip()

    if not email or not password:
        return jsonify({"success": False, "message": "Email and password required."}), 400

    db = get_db()
    try:
        user = db.execute(
            "SELECT id, name, email, role FROM users WHERE email = ? AND password_hash = ?",
            (email, hash_password(password))
        ).fetchone()

        if not user:
            return jsonify({"success": False, "message": "Invalid email or password."}), 401

        return jsonify({
            "success": True,
            "message": "Login successful.",
            "user": {
                "id":    user["id"],
                "name":  user["name"],
                "email": user["email"],
                "role":  user["role"] or "user"
            }
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        db.close()
