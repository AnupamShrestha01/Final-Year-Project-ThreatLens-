/* =================================================
   ThreatLens — PDF Report Generator
   Generates printable HTML reports from scan results
   stored in sessionStorage, then triggers print dialog
================================================= */

const REPORT_STYLES = `
    * { margin:0; padding:0; box-sizing:border-box; }
    body {
        font-family: 'Segoe UI', Arial, sans-serif;
        background: #fff;
        color: #1a1a2e;
        font-size: 13px;
        line-height: 1.5;
    }
    .page { max-width: 900px; margin: 0 auto; padding: 40px; }

    /* Header */
    .report-header {
        display: flex; justify-content: space-between; align-items: flex-start;
        border-bottom: 3px solid #3f51b5; padding-bottom: 16px; margin-bottom: 24px;
    }
    .report-logo { font-size: 1.4em; font-weight: bold; color: #3f51b5; }
    .report-logo span { color: #7c4dff; }
    .report-meta { text-align: right; font-size: 0.82em; color: #666; }
    .report-meta p { margin-bottom: 2px; }

    /* Title */
    .report-title { font-size: 1.3em; font-weight: bold; color: #1a1a2e; margin-bottom: 4px; }
    .report-subtitle { font-size: 0.88em; color: #666; margin-bottom: 24px; }

    /* Verdict banner */
    .verdict-banner {
        border-radius: 8px; padding: 16px 20px; margin-bottom: 20px;
        display: flex; align-items: center; justify-content: space-between;
        page-break-inside: avoid;
    }
    .verdict-banner.malicious  { background: #fff5f5; border: 2px solid #f44336; }
    .verdict-banner.suspicious { background: #fff8f0; border: 2px solid #ff9800; }
    .verdict-banner.clean      { background: #f0fff4; border: 2px solid #4caf50; }
    .verdict-banner.knowngood  { background: #f0f4ff; border: 2px solid #3f51b5; }

    .verdict-text { font-size: 1.4em; font-weight: bold; }
    .verdict-banner.malicious  .verdict-text { color: #f44336; }
    .verdict-banner.suspicious .verdict-text { color: #ff9800; }
    .verdict-banner.clean      .verdict-text { color: #4caf50; }
    .verdict-banner.knowngood  .verdict-text { color: #3f51b5; }

    .score-circle {
        width: 64px; height: 64px; border-radius: 50%;
        display: flex; flex-direction: column; align-items: center; justify-content: center;
        border: 3px solid; font-weight: bold;
    }
    .score-circle.malicious  { border-color: #f44336; color: #f44336; }
    .score-circle.suspicious { border-color: #ff9800; color: #ff9800; }
    .score-circle.clean      { border-color: #4caf50; color: #4caf50; }
    .score-num { font-size: 1.3em; line-height: 1; }
    .score-lbl { font-size: 0.55em; color: #999; }

    /* Sections */
    .section { margin-bottom: 22px; page-break-inside: avoid; }
    .section-title {
        font-size: 0.95em; font-weight: bold; color: #3f51b5;
        border-bottom: 1px solid #e0e0ff; padding-bottom: 6px; margin-bottom: 12px;
        text-transform: uppercase; letter-spacing: 0.5px;
    }

    /* Info grid */
    .info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
    .info-item { background: #f8f9ff; border: 1px solid #e8eaf6; border-radius: 6px; padding: 8px 12px; }
    .info-item label { font-size: 0.72em; color: #888; display: block; margin-bottom: 2px; text-transform: uppercase; }
    .info-item span  { font-size: 0.88em; color: #1a1a2e; font-weight: 500; word-break: break-all; }

    /* Engine table */
    table { width: 100%; border-collapse: collapse; font-size: 0.85em; }
    th { background: #f0f2ff; text-align: left; padding: 8px 10px; color: #3f51b5; font-weight: 600; border-bottom: 2px solid #c5cae9; }
    td { padding: 7px 10px; border-bottom: 1px solid #f0f0f0; }
    tr:nth-child(even) td { background: #fafafa; }

    /* Badges */
    .badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 0.76em; font-weight: 600; }
    .badge.Malicious  { background: #ffebee; color: #f44336; border: 1px solid #f44336; }
    .badge.Suspicious { background: #fff3e0; color: #ff9800; border: 1px solid #ff9800; }
    .badge.Clean      { background: #e8f5e9; color: #4caf50; border: 1px solid #4caf50; }
    .badge.found      { background: #ffebee; color: #f44336; }
    .badge.not_found  { background: #e8f5e9; color: #4caf50; }
    .badge.error      { background: #f5f5f5; color: #999; }

    /* Flags */
    .flag-item {
        background: #fff8f0; border-left: 3px solid #ff9800;
        padding: 6px 10px; margin-bottom: 5px; border-radius: 0 4px 4px 0;
        font-size: 0.83em; color: #333;
    }
    .flag-item.malicious { background: #fff5f5; border-left-color: #f44336; }

    /* MITRE */
    .mitre-item {
        display: inline-block; background: #f0f2ff; border: 1px solid #c5cae9;
        border-radius: 5px; padding: 4px 10px; margin: 3px; font-size: 0.8em;
    }
    .mitre-item .tid   { color: #3f51b5; font-weight: bold; margin-right: 4px; }
    .mitre-item .tname { color: #555; }

    /* Footer */
    .report-footer {
        margin-top: 30px; padding-top: 14px; border-top: 1px solid #e0e0e0;
        display: flex; justify-content: space-between; font-size: 0.76em; color: #aaa;
    }

    /* Print */
    @media print {
        body { print-color-adjust: exact; -webkit-print-color-adjust: exact; }
        .no-print { display: none !important; }
        .page { padding: 20px; }
    }
`;

// ── Helpers ────────────────────────────────────────────────────────────────
function fmt(v) { return (v !== undefined && v !== null && v !== "") ? v : "—"; }

function num(v) { return (v !== undefined && v !== null) ? v : 0; }

function nowStr() { return new Date().toLocaleString(); }

function verdictClass(v) {
    if (!v) return "clean";
    const l = v.toLowerCase();
    if (l === "malicious") return "malicious";
    if (l === "suspicious") return "suspicious";
    if (l.includes("good")) return "knowngood";
    return "clean";
}

function engineStatusBadge(status) {
    if (status === "found") return '<span class="badge found">⚠ Found</span>';
    if (status === "not_found") return '<span class="badge not_found">✓ Not Found</span>';
    if (status === "unavailable") return '<span class="badge error">Unavailable</span>';
    return '<span class="badge error">' + (status || "—") + '</span>';
}

// ── Build report HTML ──────────────────────────────────────────────────────
function buildReportHTML(data, scanType) {
    const vc = verdictClass(data.verdict);
    const score = data.threat_score || 0;
    const engines = data.engines || {};
    const flags = data.flags || [];
    const mitre = data.mitre_techniques || [];
    const meta = buildMeta(data, scanType);

    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ThreatLens Report — ${scanType.toUpperCase()} Scan</title>
    <style>${REPORT_STYLES}</style>
</head>
<body>
<div class="page">

    <!-- Header -->
    <div class="report-header">
        <div>
            <div class="report-logo">🛡️ Threat<span>Lens</span></div>
            <div style="font-size:0.78em;color:#999;margin-top:3px;">Threat Intelligence Platform</div>
        </div>
        <div class="report-meta">
            <p><strong>Report Type:</strong> ${scanType.toUpperCase()} Scan</p>
            <p><strong>Generated:</strong> ${nowStr()}</p>
            <p><strong>Classification:</strong> CONFIDENTIAL</p>
        </div>
    </div>

    <!-- Title -->
    <div class="report-title">${scanType.toUpperCase()} Threat Analysis Report</div>
    <div class="report-subtitle">Automated multi-engine threat analysis — ThreatLens v2.0</div>

    <!-- Verdict Banner -->
    <div class="verdict-banner ${vc}">
        <div>
            <div class="verdict-text">
                ${ vc === "malicious"  ? "🚨 MALICIOUS"  :
                   vc === "suspicious" ? "⚠️ SUSPICIOUS" :
                   vc === "knowngood"  ? "🛡️ KNOWN GOOD" : "✅ CLEAN" }
            </div>
            <div style="font-size:0.82em;color:#666;margin-top:4px;">
                Risk Level: <strong>${data.risk || data.risk_level || "—"}</strong>
                ${data.threat_type ? " &nbsp;|&nbsp; Type: <strong>" + data.threat_type + "</strong>" : ""}
                ${data.malware_family && data.malware_family !== "Unknown" ? " &nbsp;|&nbsp; Family: <strong>" + data.malware_family + "</strong>" : ""}
            </div>
        </div>
        <div class="score-circle ${vc}">
            <span class="score-num">${score}</span>
            <span class="score-lbl">/100</span>
        </div>
    </div>

    <!-- Scan Metadata -->
    <div class="section">
        <div class="section-title">📋 Scan Information</div>
        <div class="info-grid">${meta}</div>
    </div>

    <!-- Engine Results -->
    <div class="section">
        <div class="section-title">🔍 Engine Results Summary</div>
        <table>
            <thead><tr><th>Engine</th><th>Status</th><th>Finding</th></tr></thead>
            <tbody>${buildEngineRows(engines, scanType)}</tbody>
        </table>
    </div>

    ${ flags.length ? `
    <!-- Detection Flags -->
    <div class="section">
        <div class="section-title">🚩 Detection Flags</div>
        ${flags.map(function(f) {
            const isMal = f.toLowerCase().includes("malicious") || f.toLowerCase().includes("infected");
            return '<div class="flag-item ' + (isMal?"malicious":"") + '">' + f + '</div>';
        }).join("")}
    </div>` : ""}

    ${ mitre.length ? `
    <!-- MITRE ATT&CK -->
    <div class="section">
        <div class="section-title">🎯 MITRE ATT&CK Techniques</div>
        <div>${mitre.map(function(t) {
            return '<div class="mitre-item"><span class="tid">' + t.technique_id + '</span><span class="tname">' + t.technique_name + '</span></div>';
        }).join("")}</div>
    </div>` : ""}

    ${ buildCommunitySection(data) }

    <!-- Footer -->
    <div class="report-footer">
        <span>ThreatLens — Automated Threat Intelligence Platform</span>
        <span>Generated: ${nowStr()}</span>
    </div>

</div>

<!-- Print button (hidden on print) -->
<div class="no-print" style="position:fixed;bottom:20px;right:20px;display:flex;gap:10px;">
    <button onclick="window.print()"
        style="background:#3f51b5;color:#fff;border:none;padding:12px 24px;border-radius:8px;cursor:pointer;font-size:1em;font-weight:bold;box-shadow:0 4px 12px rgba(63,81,181,0.4);">
        🖨️ Save as PDF
    </button>
    <button onclick="window.close()"
        style="background:#f5f5f5;color:#333;border:1px solid #ddd;padding:12px 18px;border-radius:8px;cursor:pointer;font-size:1em;">
        ✕ Close
    </button>
</div>

</body></html>`;
}

// ── Metadata section ──────────────────────────────────────────────────────
function buildMeta(data, scanType) {
    const items = [];

    if (scanType === "hash") {
        items.push(["Hash Value",  data.hash      || data.input || "—"]);
        items.push(["Hash Type",   data.hash_type || "—"]);
    } else if (scanType === "url") {
        items.push(["Target URL",  data.url    || data.input || "—"]);
        items.push(["Domain",      data.domain || "—"]);
        items.push(["Input Type",  data.input_type || "—"]);
        items.push(["Resolved IP", data.resolved_ip || "—"]);
    } else if (scanType === "file") {
        items.push(["Filename",    data.filename  || "—"]);
        items.push(["File Type",   data.file_type || "—"]);
        items.push(["File Size",   data.file_size ? data.file_size + " bytes" : "—"]);
        items.push(["Entropy",     data.entropy   ? data.entropy.toFixed(2) : "—"]);
        const hashes = data.hashes || {};
        if (hashes.sha256) items.push(["SHA256", hashes.sha256]);
        if (hashes.md5)    items.push(["MD5",    hashes.md5]);
    }

    items.push(["Verdict",      data.verdict      || "—"]);
    items.push(["Threat Score", (data.threat_score || 0) + " / 100"]);
    items.push(["Risk Level",   data.risk || data.risk_level || "—"]);
    items.push(["Report Date",  nowStr()]);

    return items.map(function(item) {
        return '<div class="info-item"><label>' + item[0] + '</label><span>' + fmt(item[1]) + '</span></div>';
    }).join("");
}

// ── Engine rows ───────────────────────────────────────────────────────────
function buildEngineRows(engines, scanType) {
    const rows = [];

    const ENGINE_NAMES = {
        malwarebazaar:  "🧬 MalwareBazaar",
        virustotal:     "🛡️ VirusTotal",
        alienvault:     "👁️ AlienVault OTX",
        otx:            "👁️ AlienVault OTX",
        circl:          "🔍 CIRCL hashlookup",
        metadefender:   "🔬 MetaDefender",
        local_db:       "💾 Local DB",
        urlscan:        "🌐 URLScan.io",
        whois:          "📋 WHOIS",
        dns:            "🌍 DNS Intelligence",
        static_analysis:"📄 Static Analysis",
        yara:           "⚡ YARA Rules",
        pe_analysis:    "🔩 PE Analysis",
        behavior:       "🧪 Sandbox Behavior",
        mitre:          "🎯 MITRE Mapper",
    };

    for (const key in engines) {
        if (key === "mitre") continue;
        const eng  = engines[key];
        if (!eng || typeof eng !== "object") continue;
        const name = ENGINE_NAMES[key] || key;
        const status = eng.status || "—";

        let finding = "—";
        if (eng.malicious > 0)    finding = eng.malicious + "/" + (eng.total_engines||"?") + " engines detected";
        else if (eng.pulse_count > 0) finding = eng.pulse_count + " OTX pulses";
        else if (eng.signature)   finding = eng.signature;
        else if (eng.threat_label)finding = eng.threat_label;
        else if (eng.threat_name) finding = eng.threat_name;
        else if (eng.known_good)  finding = "Known legitimate file (trust: " + (eng.trust_score||0) + "/100)";
        else if (eng.matched_count > 0) finding = eng.matched_count + " YARA rule(s) matched";
        else if (eng.threat_score > 0)  finding = "Score: " + eng.threat_score;
        else if (status === "not_found") finding = "Not in database";
        else if (status === "found")     finding = "Match found";

        rows.push('<tr>' +
            '<td><strong>' + name + '</strong></td>' +
            '<td>' + engineStatusBadge(status) + '</td>' +
            '<td style="color:#555;">' + finding + '</td>' +
        '</tr>');
    }

    return rows.join("") || '<tr><td colspan="3" style="text-align:center;color:#999;">No engine data</td></tr>';
}

// ── Community DB section ──────────────────────────────────────────────────
function buildCommunitySection(data) {
    const c = data.community;
    if (!c || c.status === "not_found") return "";

    return `
    <div class="section">
        <div class="section-title">🌐 Community Intelligence</div>
        <div class="info-grid">
            <div class="info-item"><label>Times Seen</label><span>${c.times_seen || 0} scan(s) across all users</span></div>
            <div class="info-item"><label>Malicious Reports</label><span>${c.malicious_reports || 0}</span></div>
            <div class="info-item"><label>Last Verdict</label><span>${c.last_verdict || "—"}</span></div>
            <div class="info-item"><label>Last Seen</label><span>${c.last_seen ? c.last_seen.split(" ")[0] : "—"}</span></div>
        </div>
    </div>`;
}

// ── Public functions ───────────────────────────────────────────────────────

// Generate report for current scan in sessionStorage
function generateScanReport(scanType) {
    const keyMap = {
        file: "scanResult",
        url:  "urlScanResult",
        hash: "hashScanResult"
    };

    const raw = sessionStorage.getItem(keyMap[scanType]);
    if (!raw) {
        alert("No scan result found. Please run a scan first.");
        return;
    }

    const data = JSON.parse(raw);
    const html = buildReportHTML(data, scanType);
    const win  = window.open("", "_blank");
    win.document.write(html);
    win.document.close();
}

// Generate summary report from scan history array
function generateSummaryReport(scans, username) {
    const total     = scans.length;
    const malicious = scans.filter(function(s){ return s.verdict === "Malicious"; }).length;
    const suspicious= scans.filter(function(s){ return s.verdict === "Suspicious"; }).length;
    const clean     = scans.filter(function(s){ return s.verdict === "Clean"; }).length;
    const avgScore  = total ? Math.round(scans.reduce(function(a,s){ return a + (s.threat_score||0); }, 0) / total) : 0;

    const rows = scans.slice(0, 50).map(function(s, i) {
        const sc = s.threat_score || 0;
        const color = sc >= 70 ? "#f44336" : sc >= 30 ? "#ff9800" : "#4caf50";
        return '<tr>' +
            '<td style="color:#999;">' + (i+1) + '</td>' +
            '<td><span class="badge ' + s.scan_type + '" style="background:#f0f2ff;color:#3f51b5;border:1px solid #c5cae9;">' + s.scan_type + '</span></td>' +
            '<td style="font-family:monospace;font-size:0.8em;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + (s.filename || s.target || "—") + '</td>' +
            '<td><span class="badge ' + s.verdict + '">' + (s.verdict||"—") + '</span></td>' +
            '<td style="color:' + color + ';font-weight:bold;">' + sc + '</td>' +
            '<td style="color:#999;font-size:0.82em;">' + (s.scanned_at ? s.scanned_at.split(" ")[0] : "—") + '</td>' +
        '</tr>';
    }).join("");

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ThreatLens — Summary Report</title>
    <style>${REPORT_STYLES}</style>
</head>
<body>
<div class="page">

    <div class="report-header">
        <div>
            <div class="report-logo">🛡️ Threat<span>Lens</span></div>
            <div style="font-size:0.78em;color:#999;margin-top:3px;">Threat Intelligence Platform</div>
        </div>
        <div class="report-meta">
            <p><strong>Report Type:</strong> User Summary</p>
            <p><strong>User:</strong> ${username || "Unknown"}</p>
            <p><strong>Generated:</strong> ${nowStr()}</p>
        </div>
    </div>

    <div class="report-title">Scan Activity Summary Report</div>
    <div class="report-subtitle">Complete threat analysis history — ThreatLens v2.0</div>

    <!-- Stats -->
    <div class="section">
        <div class="section-title">📊 Overview Statistics</div>
        <div class="info-grid">
            <div class="info-item"><label>Total Scans</label><span style="font-size:1.3em;font-weight:bold;color:#3f51b5;">${total}</span></div>
            <div class="info-item"><label>Average Threat Score</label><span style="font-size:1.3em;font-weight:bold;">${avgScore}/100</span></div>
            <div class="info-item"><label>Malicious Detections</label><span style="color:#f44336;font-weight:bold;font-size:1.1em;">${malicious}</span></div>
            <div class="info-item"><label>Suspicious Detections</label><span style="color:#ff9800;font-weight:bold;font-size:1.1em;">${suspicious}</span></div>
            <div class="info-item"><label>Clean Results</label><span style="color:#4caf50;font-weight:bold;font-size:1.1em;">${clean}</span></div>
            <div class="info-item"><label>Detection Rate</label><span style="font-weight:bold;">${total ? Math.round(((malicious+suspicious)/total)*100) : 0}%</span></div>
        </div>
    </div>

    <!-- Scan History Table -->
    <div class="section">
        <div class="section-title">🕒 Scan History ${total > 50 ? "(showing latest 50)" : ""}</div>
        <table>
            <thead><tr><th>#</th><th>Type</th><th>Target</th><th>Verdict</th><th>Score</th><th>Date</th></tr></thead>
            <tbody>${rows}</tbody>
        </table>
    </div>

    <div class="report-footer">
        <span>ThreatLens — Automated Threat Intelligence Platform</span>
        <span>Generated: ${nowStr()}</span>
    </div>
</div>

<div class="no-print" style="position:fixed;bottom:20px;right:20px;display:flex;gap:10px;">
    <button onclick="window.print()"
        style="background:#3f51b5;color:#fff;border:none;padding:12px 24px;border-radius:8px;cursor:pointer;font-size:1em;font-weight:bold;box-shadow:0 4px 12px rgba(63,81,181,0.4);">
        🖨️ Save as PDF
    </button>
    <button onclick="window.close()"
        style="background:#f5f5f5;color:#333;border:1px solid #ddd;padding:12px 18px;border-radius:8px;cursor:pointer;font-size:1em;">
        ✕ Close
    </button>
</div>
</body></html>`;

    const win = window.open("", "_blank");
    win.document.write(html);
    win.document.close();
}