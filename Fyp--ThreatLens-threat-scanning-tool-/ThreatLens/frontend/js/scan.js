/* ===========================================
   scan.js — ThreatLens Scan Functions
=========================================== */

const API = "http://127.0.0.1:5000";

/* ── FILE SCAN ── */
async function scanFile() {
    const fileInput = document.getElementById("fileInput");
    const file = fileInput ? fileInput.files[0] : null;
    if (!file) return alert("Please select a file to scan.");

    const btn = document.querySelector("[onclick=\"scanFile()\"]") ||
        document.querySelector("[onclick='scanFile()']");
    if (btn) {
        btn.disabled = true;
        btn.textContent = "Scanning...";
    }

    const form = new FormData();
    form.append("file", file);
    const uid = sessionStorage.getItem("uid");
    if (uid) form.append("user_id", uid);

    try {
        const controller = new AbortController();
        const tid = setTimeout(() => controller.abort(), 120000);
        const res = await fetch(`${API}/api/scan/file`, {
            method: "POST",
            body: form,
            signal: controller.signal
        });
        clearTimeout(tid);
        const data = await res.json();
        if (data.success) {
            sessionStorage.setItem("scanResult", JSON.stringify(data.result));
            sessionStorage.setItem("lastScannedFile_name", file.name);
            sessionStorage.setItem("lastScannedFile_size", file.size);
            sessionStorage.setItem("lastScannedFile_type", file.type);
            // Store file as base64 for behavior analysis
            const reader = new FileReader();
            reader.onload = function(e) {
                sessionStorage.setItem("lastScannedFile_b64", e.target.result);
                window.location.href = "result.html";
            };
            reader.readAsDataURL(file);
        } else {
            alert(data.message || "Scan failed.");
        }
    } catch (err) {
        if (err.name === "AbortError") {
            alert("Scan timed out. Try a smaller file.");
        } else {
            alert("Cannot reach server.\nError: " + err.message);
        }
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.textContent = "Submit File";
        }
    }
}

/* ── URL SCAN ── */
async function scanURL() {
    const input = document.getElementById("urlInput");
    const value = input ? input.value.trim() : "";
    if (!value) return alert("Enter a URL, domain, or IP address.");

    const btn = document.querySelector("[onclick=\"scanURL()\"]") ||
        document.querySelector("[onclick='scanURL()']");
    if (btn) {
        btn.disabled = true;
        btn.textContent = "Scanning...";
    }

    const uid = sessionStorage.getItem("uid");
    try {
        const controller = new AbortController();
        const tid = setTimeout(() => controller.abort(), 120000);
        const res = await fetch(`${API}/api/scan/url`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ value: value, user_id: uid }),
            signal: controller.signal
        });
        clearTimeout(tid);
        const data = await res.json();
        if (data.success) {
            sessionStorage.setItem("urlScanResult", JSON.stringify(data.result));
            window.location.href = "url_result.html";
        } else {
            alert(data.message || "URL scan failed.");
        }
    } catch (err) {
        if (err.name === "AbortError") {
            alert("URL scan timed out. Please try again.");
        } else {
            alert("Cannot reach server.\nError: " + err.message);
        }
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.textContent = "Search";
        }
    }
}

/* ── HASH SCAN ── */
async function scanHash() {
    const input = document.getElementById("hashInput");
    const hash = input ? input.value.trim() : "";
    if (!hash) return alert("Enter an MD5, SHA1, or SHA256 hash.");

    const len = hash.replace(/\s/g, "").length;
    if (![32, 40, 64].includes(len)) {
        return alert("Invalid hash length.\nMD5=32, SHA1=40, SHA256=64\nYou entered " + len);
    }

    const btn = document.querySelector("[onclick=\"scanHash()\"]") ||
        document.querySelector("[onclick='scanHash()']");
    if (btn) {
        btn.disabled = true;
        btn.textContent = "Scanning...";
    }

    const uid = sessionStorage.getItem("uid");
    try {
        const controller = new AbortController();
        const tid = setTimeout(() => controller.abort(), 60000);
        const res = await fetch(`${API}/api/scan/hash`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ hash: hash, user_id: uid }),
            signal: controller.signal
        });
        clearTimeout(tid);
        const data = await res.json();
        if (data.success) {
            sessionStorage.setItem("hashScanResult", JSON.stringify(data.result));
            window.location.href = "hash_result.html";
        } else {
            alert(data.message || "Hash scan failed.");
        }
    } catch (err) {
        if (err.name === "AbortError") {
            alert("Hash scan timed out.");
        } else {
            alert("Cannot reach server.\nError: " + err.message);
        }
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.textContent = "Search";
        }
    }
}

/* ── BEHAVIOR SCAN ── */
async function scanBehavior() {
    // Get file from hidden input on result page
    const fileInput = document.getElementById("behaviorFileInput");
    const file = fileInput ? fileInput.files[0] : null;
    if (!file) {
        alert("Please select the file again for behavior analysis.");
        document.getElementById("behaviorFileInputWrap").style.display = "block";
        return;
    }

    const btn = document.getElementById("behaviorBtn");
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = "⏳ Analyzing... (up to 60s)";
    }

    const section = document.getElementById("behaviorDynamicSection");
    if (section) {
        section.style.display = "block";
        section.innerHTML = `
            <div style="text-align:center;padding:30px;color:#888">
                <div style="font-size:2rem;margin-bottom:12px">🔬</div>
                <p style="font-size:1rem;margin-bottom:6px">Running file in isolated Docker sandbox...</p>
                <p style="font-size:0.85rem;color:#555">Capturing syscalls · network activity · file operations</p>
            </div>`;
    }

    const form = new FormData();
    form.append("file", file);

    try {
        const controller = new AbortController();
        const tid = setTimeout(() => controller.abort(), 120000);
        const res = await fetch(`${API}/api/scan/behavior`, {
            method: "POST",
            body: form,
            signal: controller.signal
        });
        clearTimeout(tid);
        const data = await res.json();

        if (data.success) {
            renderBehaviorResults(data.result);
        } else {
            if (section) section.innerHTML = `
                <div style="padding:20px;color:#ff4444;text-align:center">
                    ❌ ${data.message || "Behavior analysis failed."}
                </div>`;
        }
    } catch (err) {
        if (section) section.innerHTML = err.name === "AbortError" ?
            `<div style="padding:20px;color:#ff8800;text-align:center">⏱️ Analysis timed out. Try again.</div>` :
            `<div style="padding:20px;color:#ff4444;text-align:center">❌ Cannot reach server: ${err.message}</div>`;
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = "🔬 Run Behavior Analysis";
        }
    }
}

function renderBehaviorResults(r) {
    const section = document.getElementById("behaviorDynamicSection");
    if (!section) return;

    const levelColors = {
        "HIGH": "#ff4444",
        "MEDIUM": "#ff9900",
        "LOW": "#ffcc00",
        "CLEAN": "#00cc66",
        "UNKNOWN": "#888888"
    };
    const color = levelColors[r.threat_level] || "#888";

    const syscalls = r.syscall_summary || {};
    const syscallRows = Object.entries(syscalls).map(([k, v]) =>
        `<tr>
            <td style="padding:7px 10px;color:#9ca3af;font-size:0.82rem;text-transform:capitalize">
                ${k.replace(/_/g, ' ')}
            </td>
            <td style="padding:7px 10px;font-weight:700;color:#d1d5db">${v}</td>
        </tr>`
    ).join("");

    const indicators = (r.suspicious_indicators || []).map(i =>
        `<div style="padding:8px 12px;margin-bottom:6px;background:rgba(255,136,0,0.08);
                     border-left:3px solid #ff8800;border-radius:6px;
                     color:#ffaa44;font-size:0.85rem">⚠️ ${i}</div>`
    ).join("") || `<div style="color:#555;font-size:0.85rem">No suspicious indicators detected</div>`;

    const mitreTags = (r.mitre_tags || []).map(t =>
        `<span style="padding:4px 12px;border-radius:20px;background:rgba(255,68,68,0.1);
                      color:#ff8888;border:1px solid rgba(255,68,68,0.2);
                      font-size:0.78rem;font-weight:700"
               title="${t.name}">${t.id} — ${t.name}</span>`
    ).join("") || `<span style="color:#555;font-size:0.85rem">None detected</span>`;

    const files = (r.files_accessed || []).map(f =>
        `<div style="font-size:0.78rem;color:#6b7280;padding:2px 0;font-family:monospace">${f}</div>`
    ).join("");

    section.innerHTML = `
        <div style="display:flex;align-items:center;gap:20px;margin-bottom:20px;
                    padding:16px;background:rgba(255,255,255,0.03);border-radius:10px;
                    border-left:4px solid ${color}">
            <div style="font-size:2.5rem;font-weight:900;color:${color};min-width:60px;text-align:center">
                ${r.threat_score || 0}
            </div>
            <div>
                <div style="font-size:0.75rem;color:#6b7280;text-transform:uppercase;
                            letter-spacing:0.05em;margin-bottom:4px">Behavior Threat Score</div>
                <span style="padding:4px 16px;border-radius:20px;font-weight:800;font-size:0.85rem;
                             background:${color}22;color:${color};border:1px solid ${color}44">
                    ${r.threat_level || "UNKNOWN"}
                </span>
                <div style="font-size:0.78rem;color:#555;margin-top:6px">
                    Analysis duration: ${r.duration_seconds || 0}s in isolated container
                </div>
            </div>
        </div>

        <div style="margin-bottom:16px">
            <div style="font-size:0.75rem;color:#6b7280;text-transform:uppercase;
                        letter-spacing:0.05em;margin-bottom:10px">⚠️ Suspicious Indicators</div>
            ${indicators}
        </div>

        <div style="margin-bottom:16px">
            <div style="font-size:0.75rem;color:#6b7280;text-transform:uppercase;
                        letter-spacing:0.05em;margin-bottom:10px">📊 System Call Summary</div>
            <table style="width:100%;border-collapse:collapse;background:rgba(255,255,255,0.02);border-radius:8px;overflow:hidden">
                <thead>
                    <tr style="border-bottom:1px solid rgba(255,255,255,0.06)">
                        <th style="padding:8px 10px;text-align:left;font-size:0.72rem;color:#4b5563">Operation</th>
                        <th style="padding:8px 10px;text-align:left;font-size:0.72rem;color:#4b5563">Count</th>
                    </tr>
                </thead>
                <tbody>${syscallRows}</tbody>
            </table>
        </div>

        <div style="margin-bottom:16px">
            <div style="font-size:0.75rem;color:#6b7280;text-transform:uppercase;
                        letter-spacing:0.05em;margin-bottom:10px">🎯 MITRE ATT&CK Techniques</div>
            <div style="display:flex;gap:8px;flex-wrap:wrap">${mitreTags}</div>
        </div>

        <details style="margin-bottom:8px">
            <summary style="cursor:pointer;font-size:0.82rem;color:#6b7280;padding:6px 0">
                📁 Files Accessed (${(r.files_accessed || []).length})
            </summary>
            <div style="margin-top:8px;padding:10px;background:rgba(255,255,255,0.02);
                        border-radius:8px;max-height:200px;overflow-y:auto">
                ${files || '<span style="color:#555;font-size:0.82rem">None recorded</span>'}
            </div>
        </details>
    `;
}