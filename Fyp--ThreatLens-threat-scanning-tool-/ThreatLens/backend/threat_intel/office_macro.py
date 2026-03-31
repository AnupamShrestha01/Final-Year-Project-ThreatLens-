"""
backend/threat_intel/office_macro.py
Office Macro & Document Threat Detection
- Detects VBA macros in Word/Excel/PowerPoint files
- Detects auto-open/auto-exec macros
- Detects suspicious VBA patterns (shell commands, downloads, obfuscation)
- Uses oletools (pip install oletools) — no API needed
"""
import os, re

# Suspicious VBA patterns
VBA_DANGEROUS = [
    (r"Shell\s*\(", "Shell execution command",     "critical"),
    (r"WScript\.Shell", "WScript shell access",    "critical"),
    (r"CreateObject\s*\(", "COM object creation",  "high"),
    (r"powershell", "PowerShell invocation",        "critical"),
    (r"cmd\.exe", "CMD execution",                  "critical"),
    (r"URLDownloadToFile", "File download from URL","critical"),
    (r"XMLHTTP", "HTTP request (download)",         "high"),
    (r"WinHttp", "HTTP request (download)",         "high"),
    (r"AutoOpen|Auto_Open", "Auto-open macro",      "high"),
    (r"AutoClose|Auto_Close", "Auto-close macro",   "medium"),
    (r"Document_Open", "Document open trigger",     "high"),
    (r"Workbook_Open", "Workbook open trigger",     "high"),
    (r"Chr\s*\(\d+\)", "Character obfuscation",     "medium"),
    (r"Base64", "Base64 encoding (obfuscation)",    "medium"),
    (r"Environ\s*\(", "Environment variable access","medium"),
    (r"RegWrite|RegRead", "Registry access",        "high"),
    (r"taskkill|tasklist", "Process manipulation",  "high"),
    (r"net\s+user|net\s+localgroup", "User management command", "critical"),
    (r"certutil", "Certutil abuse (downloader)",    "critical"),
    (r"bitsadmin", "BITSAdmin abuse (downloader)",  "critical"),
    (r"mshta", "MSHTA abuse",                       "critical"),
    (r"wscript|cscript", "Script execution",        "high"),
]

OFFICE_EXTENSIONS = {
    ".doc", ".docx", ".docm",
    ".xls", ".xlsx", ".xlsm", ".xlsb",
    ".ppt", ".pptx", ".pptm",
    ".odt", ".ods", ".odp"
}


def analyze_office_macros(file_data: bytes, filename: str) -> dict:
    """Analyze Office document for malicious macros."""
    ext = os.path.splitext(filename.lower())[1]

    if ext not in OFFICE_EXTENSIONS:
        return {"engine": "Macro Analysis", "status": "not_applicable",
                "verdict": "N/A", "message": "Not an Office document"}

    flags      = []
    score      = 0
    has_macros = False
    vba_code   = ""

    # ── Try oletools first ────────────────────────────────────────────────
    try:
        import tempfile, os as _os
        tmp = tempfile.NamedTemporaryFile(suffix=ext, delete=False)
        tmp.write(file_data)
        tmp.close()

        try:
            from oletools.olevba import VBA_Parser
            vba_parser = VBA_Parser(tmp.name, data=file_data)

            if vba_parser.detect_vba_macros():
                has_macros = True
                flags.append("VBA macros detected in document")
                score += 30

                # Extract and analyze VBA code
                for (filename_vba, stream_path, vba_filename, code) in vba_parser.extract_macros():
                    vba_code += code + "\n"

                # Check IOCs
                iocs = vba_parser.extract_iocs()
                urls_found = [i for i in iocs if i[0] == "URL"]
                if urls_found:
                    flags.append(f"URLs embedded in macro: {len(urls_found)} found")
                    score += 20

            vba_parser.close()
        finally:
            _os.unlink(tmp.name)

    except ImportError:
        # oletools not installed — fall back to pattern matching on raw bytes
        flags.append("Note: Install oletools for deeper macro analysis (pip install oletools)")
        vba_code = _extract_vba_fallback(file_data)
        if vba_code:
            has_macros = True
            flags.append("Macro-like content detected in document bytes")
            score += 25

    except Exception as e:
        # Still try fallback
        vba_code = _extract_vba_fallback(file_data)
        if vba_code:
            has_macros = True
            score += 20

    # ── Analyze VBA code patterns ─────────────────────────────────────────
    suspicious_patterns = []
    if vba_code:
        for pattern, description, severity in VBA_DANGEROUS:
            if re.search(pattern, vba_code, re.IGNORECASE):
                suspicious_patterns.append({
                    "pattern":     description,
                    "severity":    severity,
                })
                if severity == "critical": score += 35
                elif severity == "high":   score += 20
                elif severity == "medium": score += 10
                flags.append(f"[{severity.upper()}] {description}")

    # ── Check for OLE objects (embedded executables) ──────────────────────
    if b"D0CF11E0" in file_data.hex().upper().encode() or file_data[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
        if not has_macros:
            flags.append("OLE compound document format detected")
            score += 5

    # ── Check for embedded PE files ───────────────────────────────────────
    if b'MZ' in file_data[100:]:
        flags.append("Embedded executable (PE file) detected inside document")
        score += 50

    score = min(score, 100)

    if score >= 60:    verdict = "Malicious"
    elif score >= 30:  verdict = "Suspicious"
    elif has_macros:   verdict = "Suspicious"
    else:              verdict = "Clean"

    return {
        "engine":      "Macro Analysis",
        "status":      "found" if score > 0 or has_macros else "clean",
        "verdict":     verdict,
        "score":       score,
        "has_macros":  has_macros,
        "flags":       flags,
        "patterns":    suspicious_patterns[:8],
        "threat_type": "Macro Malware" if score >= 60 else ("Suspicious Macro" if score >= 30 else "None"),
    }


def _extract_vba_fallback(file_data: bytes) -> str:
    """Basic VBA extraction without oletools — looks for VBA strings in bytes."""
    try:
        text = file_data.decode("latin-1", errors="replace")
        # Look for VBA-like content
        vba_markers = ["Sub ", "Function ", "Dim ", "Shell", "CreateObject", "AutoOpen"]
        if any(m in text for m in vba_markers):
            return text
    except Exception:
        pass
    return ""