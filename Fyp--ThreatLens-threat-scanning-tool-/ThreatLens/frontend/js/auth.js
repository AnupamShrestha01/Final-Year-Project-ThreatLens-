/* ===========================================
   auth.js — ThreatLens Authentication
   Connects to Flask backend API
=========================================== */

const API = "http://127.0.0.1:5000";

/* ── REGISTER ── */
async function register() {
    const name = document.getElementById("regName").value.trim();
    const email = document.getElementById("regEmail").value.trim();
    const password = document.getElementById("regPassword").value.trim();
    const msg = document.getElementById("registerMsg");

    if (!name || !email || !password) {
        showMsg(msg, "All fields are required.", "red");
        return;
    }
    if (password.length < 6) {
        showMsg(msg, "Password must be at least 6 characters.", "red");
        return;
    }

    showMsg(msg, "Creating account...", "#888");

    try {
        const res = await fetch(`${API}/api/auth/register`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name, email, password })
        });
        const data = await res.json();

        if (data.success) {
            showMsg(msg, "Account created! Redirecting to login...", "green");
            setTimeout(() => window.location.href = "login.html", 1400);
        } else {
            showMsg(msg, data.message || "Registration failed.", "red");
        }
    } catch (err) {
        showMsg(msg, "Cannot reach server. Is the backend running?", "red");
    }
}

/* ── LOGIN ── */
async function login() {
    const email = document.getElementById("loginEmail").value.trim();
    const password = document.getElementById("loginPassword").value.trim();
    const error = document.getElementById("loginError");

    if (!email || !password) {
        showMsg(error, "Email and password are required.", "red");
        return;
    }

    showMsg(error, "Signing in...", "#888");

    try {
        const res = await fetch(`${API}/api/auth/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, password })
        });
        const data = await res.json();

        if (data.success) {
            sessionStorage.setItem("uid", data.user.id);
            sessionStorage.setItem("userName", data.user.name);
            sessionStorage.setItem("userEmail", data.user.email);
            sessionStorage.setItem("userRole", data.user.role || "user");
            window.location.href = "index.html";
        } else {
            showMsg(error, data.message || "Invalid credentials.", "red");
        }
    } catch (err) {
        showMsg(error, "Cannot reach server. Is the backend running?", "red");
    }
}

/* ── HELPER ── */
function showMsg(el, text, color) {
    if (!el) return;
    el.textContent = text;
    el.style.color = color;
}

/* Allow Enter key to submit */
document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll("input").forEach(input => {
        input.addEventListener("keydown", e => {
            if (e.key === "Enter") {
                const btn = document.querySelector("button");
                if (btn) btn.click();
            }
        });
    });
});