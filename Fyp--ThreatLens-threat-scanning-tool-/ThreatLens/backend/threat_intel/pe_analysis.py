"""
backend/threat_intel/pe_analysis.py
Deep PE (Windows Executable) Header Analysis
Detects: packing, obfuscation, suspicious imports, anomalies
Pure Python — no API, no external library needed
"""
import struct, math, re, os
from collections import Counter

# Suspicious imports that malware commonly uses
SUSPICIOUS_IMPORTS = {
    # Process injection
    "VirtualAllocEx":    ("Process Injection",    "critical"),
    "WriteProcessMemory":("Process Injection",    "critical"),
    "CreateRemoteThread":("Process Injection",    "critical"),
    "NtUnmapViewOfSection":("Process Hollowing",  "critical"),
    # Anti-analysis
    "IsDebuggerPresent": ("Anti-Debug",           "high"),
    "CheckRemoteDebuggerPresent":("Anti-Debug",   "high"),
    "NtQueryInformationProcess":("Anti-Debug",    "high"),
    "GetTickCount":      ("Anti-Analysis Timing", "medium"),
    "QueryPerformanceCounter":("Anti-Analysis",   "medium"),
    # Network
    "WinHttpOpen":       ("Network Communication","medium"),
    "InternetOpenUrl":   ("Network Communication","medium"),
    "URLDownloadToFile": ("File Download",        "high"),
    "WSAStartup":        ("Network Socket",       "medium"),
    # Crypto
    "CryptEncrypt":      ("Encryption (Ransomware?)","high"),
    "CryptDecrypt":      ("Encryption",           "medium"),
    # Persistence
    "RegSetValueEx":     ("Registry Modification","high"),
    "CreateService":     ("Service Installation", "high"),
    "StartService":      ("Service Start",        "medium"),
    # Privilege
    "AdjustTokenPrivileges":("Privilege Escalation","high"),
    "LookupPrivilegeValue":("Privilege Escalation","medium"),
    # File ops
    "DeleteFile":        ("File Deletion",        "medium"),
    "MoveFileEx":        ("File Movement",        "low"),
    # Shellcode
    "VirtualProtect":    ("Memory Protection Change","high"),
    "VirtualAlloc":      ("Memory Allocation",    "medium"),
}

PACKERS = [
    (b"UPX0", "UPX Packer"),
    (b"UPX1", "UPX Packer"),
    (b"UPX!", "UPX Packer"),
    (b"MPRESS", "MPRESS Packer"),
    (b".nsp0", "NsPack Packer"),
    (b"PEtite", "PEtite Packer"),
    (b"FSG!", "FSG Packer"),
    (b"ASPack", "ASPack Packer"),
    (b"PECompact", "PECompact"),
    (b"Themida", "Themida Protector"),
    (b"WinLicense", "WinLicense Protector"),
    (b"VMProtect", "VMProtect"),
]


def _entropy(data: bytes) -> float:
    if not data: return 0.0
    counts = Counter(data)
    total  = len(data)
    return -sum((c/total) * math.log2(c/total) for c in counts.values() if c > 0)


def analyze_pe(file_data: bytes, filename: str) -> dict:
    """Deep PE header analysis."""
    ext = os.path.splitext(filename.lower())[1]

    # Only analyze PE-compatible files
    pe_extensions = {".exe", ".dll", ".sys", ".drv", ".scr", ".ocx", ".com"}
    if ext not in pe_extensions and not file_data[:2] == b'MZ':
        return {"engine": "PE Analysis", "status": "not_applicable",
                "verdict": "N/A", "message": "Not a PE file"}

    if file_data[:2] != b'MZ':
        return {"engine": "PE Analysis", "status": "not_applicable",
                "verdict": "N/A", "message": "Not a valid PE file (no MZ header)"}

    flags   = []
    score   = 0
    details = {}

    try:
        # ── Parse PE header ───────────────────────────────────────────────
        # e_lfanew offset at 0x3C
        if len(file_data) < 0x40:
            return {"engine": "PE Analysis", "status": "error", "error": "File too small"}

        e_lfanew = struct.unpack_from("<I", file_data, 0x3C)[0]
        if e_lfanew + 4 > len(file_data):
            return {"engine": "PE Analysis", "status": "error", "error": "Invalid PE offset"}

        pe_sig = file_data[e_lfanew:e_lfanew+4]
        if pe_sig != b'PE\x00\x00':
            flags.append("Invalid PE signature — possibly corrupted or packed")
            score += 20

        # COFF header
        coff_offset = e_lfanew + 4
        if coff_offset + 20 > len(file_data):
            return {"engine": "PE Analysis", "status": "error", "error": "Truncated COFF header"}

        machine, num_sections, timestamp, _, _, opt_header_size, characteristics = \
            struct.unpack_from("<HHIIIHH", file_data, coff_offset)

        import datetime
        try:
            ts = datetime.datetime.utcfromtimestamp(timestamp)
            compile_time = ts.strftime("%Y-%m-%d %H:%M:%S UTC")
            # Future timestamp = suspicious
            if ts > datetime.datetime.utcnow():
                flags.append(f"Future compile timestamp ({compile_time}) — timestamp manipulation")
                score += 20
            # Very old timestamp = suspicious (before 2000)
            elif ts.year < 2000:
                flags.append(f"Anomalous compile timestamp ({compile_time})")
                score += 10
        except:
            compile_time = "Invalid"
            flags.append("Invalid compile timestamp")
            score += 10

        machine_types = {0x14c: "x86", 0x8664: "x64", 0x1c0: "ARM", 0xaa64: "ARM64"}
        arch = machine_types.get(machine, f"Unknown (0x{machine:04x})")

        details["architecture"]   = arch
        details["num_sections"]   = num_sections
        details["compile_time"]   = compile_time
        details["characteristics"] = f"0x{characteristics:04x}"

        # ── Section analysis ──────────────────────────────────────────────
        opt_offset = coff_offset + 20
        sect_offset = opt_offset + opt_header_size
        high_entropy_sections = []

        for i in range(min(num_sections, 20)):
            s_off = sect_offset + i * 40
            if s_off + 40 > len(file_data): break
            try:
                name       = file_data[s_off:s_off+8].rstrip(b'\x00').decode("ascii", errors="replace")
                vsize      = struct.unpack_from("<I", file_data, s_off+8)[0]
                raw_offset = struct.unpack_from("<I", file_data, s_off+20)[0]
                raw_size   = struct.unpack_from("<I", file_data, s_off+16)[0]
                sect_chars = struct.unpack_from("<I", file_data, s_off+36)[0]

                if raw_size > 0 and raw_offset + raw_size <= len(file_data):
                    sect_data = file_data[raw_offset:raw_offset+raw_size]
                    ent = _entropy(sect_data)
                    if ent > 7.2:
                        high_entropy_sections.append(f"{name} ({ent:.2f})")

                # Section with exec + write = suspicious
                EXEC  = 0x20000000
                WRITE = 0x80000000
                if (sect_chars & EXEC) and (sect_chars & WRITE):
                    flags.append(f"Section '{name}' is both writable and executable — shellcode indicator")
                    score += 25

                # Virtual size >> raw size = packed
                if vsize > 0 and raw_size > 0 and vsize / raw_size > 10:
                    flags.append(f"Section '{name}' virtual size >> raw size — likely packed")
                    score += 20

            except Exception:
                continue

        if high_entropy_sections:
            flags.append(f"High entropy sections (packed/encrypted): {', '.join(high_entropy_sections)}")
            score += 30

        # ── Packer detection ──────────────────────────────────────────────
        detected_packers = []
        for sig, name in PACKERS:
            if sig in file_data[:0x2000]:
                detected_packers.append(name)
        if detected_packers:
            flags.append(f"Packer detected: {', '.join(detected_packers)}")
            score += 30
            details["packers"] = detected_packers

        # ── Import table analysis ─────────────────────────────────────────
        suspicious_found = []
        raw_str = file_data.decode("latin-1", errors="replace")
        for imp, (category, severity) in SUSPICIOUS_IMPORTS.items():
            if imp in raw_str:
                suspicious_found.append({"name": imp, "category": category, "severity": severity})
                if severity == "critical": score += 15
                elif severity == "high":   score += 8
                elif severity == "medium": score += 4

        if suspicious_found:
            categories = list(set(s["category"] for s in suspicious_found))
            flags.append(f"Suspicious imports: {', '.join(categories[:4])}")

        details["suspicious_imports"] = suspicious_found[:10]

        # ── String analysis ───────────────────────────────────────────────
        # Check for hardcoded IPs
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', raw_str)
        private_ranges = ("192.168.", "10.", "172.16.", "127.", "0.0.0.0")
        public_ips = [ip for ip in set(ips) if not any(ip.startswith(p) for p in private_ranges)]
        if public_ips:
            flags.append(f"Hardcoded public IP addresses: {', '.join(public_ips[:3])}")
            score += 15
            details["hardcoded_ips"] = public_ips[:5]

        # Check for suspicious strings
        suspicious_strings = []
        sus_patterns = ["cmd.exe", "powershell", "regedit", "schtasks", "netsh",
                        "mimikatz", "meterpreter", "cobalt strike", "beacon"]
        for s in sus_patterns:
            if s.lower() in raw_str.lower():
                suspicious_strings.append(s)
        if suspicious_strings:
            flags.append(f"Suspicious strings: {', '.join(suspicious_strings[:4])}")
            score += 20
            details["suspicious_strings"] = suspicious_strings

        # ── Overall entropy ───────────────────────────────────────────────
        overall_entropy = _entropy(file_data)
        details["overall_entropy"] = round(overall_entropy, 3)
        if overall_entropy > 7.5:
            flags.append(f"Very high overall entropy ({overall_entropy:.2f}) — heavily packed/encrypted")
            score += 20

    except Exception as e:
        return {"engine": "PE Analysis", "status": "error", "error": str(e)[:100]}

    score = min(score, 100)

    if score >= 60:    verdict = "Malicious"
    elif score >= 30:  verdict = "Suspicious"
    else:              verdict = "Clean"

    threat_type = "Clean"
    if detected_packers if 'detected_packers' in dir() else False:
        threat_type = "Packed Executable"
    if any(s["severity"] == "critical" for s in suspicious_found):
        threat_type = "Trojan / RAT"
    if score >= 70:
        threat_type = "Malware"

    return {
        "engine":      "PE Analysis",
        "status":      "found" if score > 0 else "clean",
        "verdict":     verdict,
        "score":       score,
        "threat_type": threat_type,
        "flags":       flags,
        "details":     details,
        "suspicious_imports": suspicious_found[:10],
    }