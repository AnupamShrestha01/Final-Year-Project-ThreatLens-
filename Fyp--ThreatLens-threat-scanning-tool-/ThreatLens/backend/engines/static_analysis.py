"""
backend/engines/static_analysis.py
Deep static analysis for uploaded files — PE headers, embedded strings,
suspicious patterns, file type detection (no magic lib needed).
"""
import hashlib
import struct
import re
import math
import os


# ── MIME / file type from magic bytes ──────────────────────────────────────
MAGIC_BYTES = {
    b"\x4d\x5a": "PE/EXE (Windows Executable)",
    b"\x7fELF": "ELF (Linux Executable)",
    b"\xca\xfe\xba\xbe": "Mach-O Universal Binary",
    b"\xce\xfa\xed\xfe": "Mach-O 32-bit",
    b"\xcf\xfa\xed\xfe": "Mach-O 64-bit",
    b"PK\x03\x04": "ZIP/Office/APK Archive",
    b"%PDF": "PDF Document",
    b"\x89PNG": "PNG Image",
    b"\xff\xd8\xff": "JPEG Image",
    b"GIF87a": "GIF Image",
    b"GIF89a": "GIF Image",
    b"\x1f\x8b": "GZIP Archive",
    b"BZh": "BZIP2 Archive",
    b"\xfd7zXZ": "XZ Archive",
    b"Rar!": "RAR Archive",
    b"MSCF": "Microsoft CAB",
    b"<?php": "PHP Script",
    b"#!/": "Shell Script",
    b"\xd0\xcf\x11\xe0": "Microsoft Office (Legacy)",
}

DANGEROUS_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".scr", ".pif", ".com", ".lnk", ".reg", ".hta", ".wsf",
    ".jar", ".msi", ".apk", ".app", ".dmg", ".sh", ".php"
}

SUSPICIOUS_STRINGS = [
    # PowerShell obfuscation
    r"powershell\s*-[Ee][Nn][Cc]", r"invoke-expression", r"iex\(",
    r"downloadstring", r"webclient", r"net\.webClient",
    # Shellcode / injection
    r"virtualalloc", r"writeprocessmemory", r"createremotethread",
    r"shellexecute", r"winexec", r"loadlibrary",
    # Obfuscation patterns
    r"base64_decode", r"eval\(", r"exec\(", r"system\(",
    r"chr\(", r"\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}",
    # Ransom / crypto
    r"ransomware", r"decrypt_files", r"your files are encrypted",
    r"bitcoin", r"cryptolocker", r"locky",
    # Network C2
    r"http://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    r"\.onion", r"pastebin\.com",
    # Registry persistence
    r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    r"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
]


def compute_hashes(data: bytes) -> dict:
    return {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def detect_file_type(data: bytes) -> str:
    for magic, desc in MAGIC_BYTES.items():
        if data[:len(magic)] == magic:
            return desc
    return "Unknown / Generic"


def calc_entropy(data: bytes) -> float:
    """Shannon entropy 0-8. >7 suggests packed/encrypted content."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    entropy = 0.0
    length = len(data)
    for f in freq:
        if f > 0:
            p = f / length
            entropy -= p * math.log2(p)
    return round(entropy, 2)


def analyze_pe_imports(data: bytes) -> list:
    """Naive PE import hint — look for common malware DLL strings."""
    imports_found = []
    malware_imports = [b"WSAStartup", b"connect", b"CreateProcess",
                       b"VirtualAlloc", b"WriteProcessMemory",
                       b"CreateRemoteThread", b"OpenProcess",
                       b"RegSetValueEx", b"URLDownloadToFile"]
    text = data.replace(b"\x00", b" ")
    for imp in malware_imports:
        if imp in text:
            imports_found.append(imp.decode())
    return imports_found


def scan_strings(data: bytes) -> list:
    """Scan for suspicious string patterns."""
    matches = []
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        text = ""

    for pattern in SUSPICIOUS_STRINGS:
        try:
            found = re.search(pattern, text, re.IGNORECASE)
            if found:
                matches.append(f"Suspicious pattern: `{pattern[:50]}`")
        except Exception:
            pass
    return list(set(matches))


def analyze_file(file_data: bytes, filename: str = "") -> dict:
    """
    Main entry point. Returns a structured analysis result dict.
    """
    hashes = compute_hashes(file_data)
    file_type = detect_file_type(file_data)
    entropy = calc_entropy(file_data)
    ext = os.path.splitext(filename)[1].lower() if filename else ""
    suspicious_strings = scan_strings(file_data)
    pe_imports = []
    if file_type.startswith("PE"):
        pe_imports = analyze_pe_imports(file_data)

    # ── Scoring ─────────────────────────────────────────────────────────────
    score = 0
    flags = []

    # Dangerous extension
    if ext in DANGEROUS_EXTENSIONS:
        score += 25
        flags.append(f"Dangerous file extension: {ext}")

    # High entropy (packed/encrypted)
    if entropy > 7.2:
        score += 20
        flags.append(f"Very high entropy ({entropy}) — possibly packed or encrypted")
    elif entropy > 6.5:
        score += 10
        flags.append(f"High entropy ({entropy}) — content may be obfuscated")

    # Suspicious strings
    if suspicious_strings:
        score += min(len(suspicious_strings) * 8, 30)
        flags.extend(suspicious_strings[:5])

    # Suspicious PE imports
    if pe_imports:
        score += min(len(pe_imports) * 6, 20)
        flags.append(f"Suspicious API imports: {', '.join(pe_imports[:5])}")

    # File too small to be a real doc but .docx/.xlsx
    if ext in {".docx", ".xlsx", ".pptx"} and len(file_data) < 2048:
        score += 15
        flags.append("Suspiciously small Office document")

    # Clamp
    score = min(score, 100)

    # Verdict
    if score >= 70:
        verdict = "Malicious"
        risk = "Critical"
    elif score >= 40:
        verdict = "Suspicious"
        risk = "High"
    elif score >= 20:
        verdict = "Potentially Unwanted"
        risk = "Medium"
    else:
        verdict = "Clean"
        risk = "Low"

    return {
        "engine": "ThreatLens Static Analysis",
        "file_type": file_type,
        "file_size": len(file_data),
        "entropy": entropy,
        "hashes": hashes,
        "threat_score": score,
        "verdict": verdict,
        "risk": risk,
        "flags": flags,
        "pe_suspicious_imports": pe_imports,
        "suspicious_strings_count": len(suspicious_strings),
    }
