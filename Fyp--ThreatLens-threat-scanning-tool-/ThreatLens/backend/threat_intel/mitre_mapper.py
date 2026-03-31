"""
backend/threat_intel/mitre_mapper.py
Offline MITRE ATT&CK mapping — no API, no internet needed.

Maps PE suspicious imports, YARA rule matches, and string indicators
directly to ATT&CK technique IDs with tactic, description, and URL.

Usage:
    from backend.threat_intel.mitre_mapper import map_to_mitre
    results = map_to_mitre(pe_result, yara_result, static_result)
"""

# ══════════════════════════════════════════════════════════════════════════
#  MITRE ATT&CK TECHNIQUE DATABASE (Offline)
#  Format: "T-ID": { id, name, tactic, tactic_id, description, url }
# ══════════════════════════════════════════════════════════════════════════
TECHNIQUES = {
    # ── Defense Evasion ───────────────────────────────────────────────────
    "T1055": {
        "id": "T1055", "name": "Process Injection",
        "tactic": "Defense Evasion / Privilege Escalation", "tactic_id": "TA0005",
        "description": "Injecting code into another process to evade defenses and elevate privileges.",
        "url": "https://attack.mitre.org/techniques/T1055/"
    },
    "T1055.001": {
        "id": "T1055.001", "name": "Process Injection: DLL Injection",
        "tactic": "Defense Evasion", "tactic_id": "TA0005",
        "description": "Injecting a malicious DLL into a legitimate process.",
        "url": "https://attack.mitre.org/techniques/T1055/001/"
    },
    "T1055.002": {
        "id": "T1055.002", "name": "Process Injection: Portable Executable Injection",
        "tactic": "Defense Evasion", "tactic_id": "TA0005",
        "description": "Injecting a PE directly into a running process.",
        "url": "https://attack.mitre.org/techniques/T1055/002/"
    },
    "T1055.003": {
        "id": "T1055.003", "name": "Process Injection: Thread Execution Hijacking",
        "tactic": "Defense Evasion", "tactic_id": "TA0005",
        "description": "Creating a remote thread in another process to execute injected code.",
        "url": "https://attack.mitre.org/techniques/T1055/003/"
    },
    "T1055.012": {
        "id": "T1055.012", "name": "Process Injection: Process Hollowing",
        "tactic": "Defense Evasion", "tactic_id": "TA0005",
        "description": "Unmapping a legitimate process and replacing it with malicious code.",
        "url": "https://attack.mitre.org/techniques/T1055/012/"
    },
    "T1622": {
        "id": "T1622", "name": "Debugger Evasion",
        "tactic": "Defense Evasion", "tactic_id": "TA0005",
        "description": "Detecting and evading debuggers to prevent analysis.",
        "url": "https://attack.mitre.org/techniques/T1622/"
    },
    "T1027": {
        "id": "T1027", "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion", "tactic_id": "TA0005",
        "description": "Making code/files difficult to discover or analyze (packing, encryption).",
        "url": "https://attack.mitre.org/techniques/T1027/"
    },
    "T1027.002": {
        "id": "T1027.002", "name": "Software Packing",
        "tactic": "Defense Evasion", "tactic_id": "TA0005",
        "description": "Using packers like UPX, Themida, VMProtect to compress/encrypt malware.",
        "url": "https://attack.mitre.org/techniques/T1027/002/"
    },
    "T1620": {
        "id": "T1620", "name": "Reflective Code Loading",
        "tactic": "Defense Evasion", "tactic_id": "TA0005",
        "description": "Loading code into a process without writing to disk.",
        "url": "https://attack.mitre.org/techniques/T1620/"
    },
    "T1562.001": {
        "id": "T1562.001", "name": "Impair Defenses: Disable or Modify Tools",
        "tactic": "Defense Evasion", "tactic_id": "TA0005",
        "description": "Disabling security tools such as AV or AMSI.",
        "url": "https://attack.mitre.org/techniques/T1562/001/"
    },

    # ── Persistence ───────────────────────────────────────────────────────
    "T1547.001": {
        "id": "T1547.001", "name": "Boot/Logon Autostart: Registry Run Keys",
        "tactic": "Persistence", "tactic_id": "TA0003",
        "description": "Adding registry run keys to execute malware on system startup.",
        "url": "https://attack.mitre.org/techniques/T1547/001/"
    },
    "T1543.003": {
        "id": "T1543.003", "name": "Create or Modify System Process: Windows Service",
        "tactic": "Persistence", "tactic_id": "TA0003",
        "description": "Creating or modifying Windows services for persistence.",
        "url": "https://attack.mitre.org/techniques/T1543/003/"
    },
    "T1053.005": {
        "id": "T1053.005", "name": "Scheduled Task/Job: Scheduled Task",
        "tactic": "Persistence", "tactic_id": "TA0003",
        "description": "Using Windows Task Scheduler to execute malicious code.",
        "url": "https://attack.mitre.org/techniques/T1053/005/"
    },

    # ── Privilege Escalation ──────────────────────────────────────────────
    "T1134": {
        "id": "T1134", "name": "Access Token Manipulation",
        "tactic": "Privilege Escalation", "tactic_id": "TA0004",
        "description": "Manipulating access tokens to operate with elevated privileges.",
        "url": "https://attack.mitre.org/techniques/T1134/"
    },
    "T1134.001": {
        "id": "T1134.001", "name": "Access Token Manipulation: Token Impersonation",
        "tactic": "Privilege Escalation", "tactic_id": "TA0004",
        "description": "Impersonating a logged-on user's access token.",
        "url": "https://attack.mitre.org/techniques/T1134/001/"
    },

    # ── Credential Access ─────────────────────────────────────────────────
    "T1056.001": {
        "id": "T1056.001", "name": "Input Capture: Keylogging",
        "tactic": "Credential Access", "tactic_id": "TA0006",
        "description": "Capturing keystrokes to obtain credentials.",
        "url": "https://attack.mitre.org/techniques/T1056/001/"
    },
    "T1003": {
        "id": "T1003", "name": "OS Credential Dumping",
        "tactic": "Credential Access", "tactic_id": "TA0006",
        "description": "Dumping credentials from the OS, memory, or files (e.g. Mimikatz).",
        "url": "https://attack.mitre.org/techniques/T1003/"
    },

    # ── Execution ─────────────────────────────────────────────────────────
    "T1059.001": {
        "id": "T1059.001", "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution", "tactic_id": "TA0002",
        "description": "Using PowerShell to execute malicious commands.",
        "url": "https://attack.mitre.org/techniques/T1059/001/"
    },
    "T1059.003": {
        "id": "T1059.003", "name": "Command and Scripting Interpreter: Windows Command Shell",
        "tactic": "Execution", "tactic_id": "TA0002",
        "description": "Using cmd.exe to execute commands.",
        "url": "https://attack.mitre.org/techniques/T1059/003/"
    },
    "T1106": {
        "id": "T1106", "name": "Native API",
        "tactic": "Execution", "tactic_id": "TA0002",
        "description": "Using Windows native APIs directly to execute code.",
        "url": "https://attack.mitre.org/techniques/T1106/"
    },

    # ── Command and Control ───────────────────────────────────────────────
    "T1071.001": {
        "id": "T1071.001", "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control", "tactic_id": "TA0011",
        "description": "Using HTTP/HTTPS for C2 communication.",
        "url": "https://attack.mitre.org/techniques/T1071/001/"
    },
    "T1095": {
        "id": "T1095", "name": "Non-Application Layer Protocol",
        "tactic": "Command and Control", "tactic_id": "TA0011",
        "description": "Using raw TCP/UDP sockets for C2 communication.",
        "url": "https://attack.mitre.org/techniques/T1095/"
    },
    "T1219": {
        "id": "T1219", "name": "Remote Access Software",
        "tactic": "Command and Control", "tactic_id": "TA0011",
        "description": "Using remote access tools for C2 (RAT).",
        "url": "https://attack.mitre.org/techniques/T1219/"
    },

    # ── Impact ────────────────────────────────────────────────────────────
    "T1486": {
        "id": "T1486", "name": "Data Encrypted for Impact",
        "tactic": "Impact", "tactic_id": "TA0040",
        "description": "Encrypting files to extort victims — ransomware.",
        "url": "https://attack.mitre.org/techniques/T1486/"
    },
    "T1490": {
        "id": "T1490", "name": "Inhibit System Recovery",
        "tactic": "Impact", "tactic_id": "TA0040",
        "description": "Deleting shadow copies or backups to prevent recovery.",
        "url": "https://attack.mitre.org/techniques/T1490/"
    },

    # ── Discovery ─────────────────────────────────────────────────────────
    "T1082": {
        "id": "T1082", "name": "System Information Discovery",
        "tactic": "Discovery", "tactic_id": "TA0007",
        "description": "Gathering system information like OS version and architecture.",
        "url": "https://attack.mitre.org/techniques/T1082/"
    },
    "T1057": {
        "id": "T1057", "name": "Process Discovery",
        "tactic": "Discovery", "tactic_id": "TA0007",
        "description": "Enumerating running processes.",
        "url": "https://attack.mitre.org/techniques/T1057/"
    },

    # ── Defense Evasion / Execution ───────────────────────────────────────
    "T1218": {
        "id": "T1218", "name": "System Binary Proxy Execution",
        "tactic": "Defense Evasion", "tactic_id": "TA0005",
        "description": "Using trusted Windows binaries to execute malicious code.",
        "url": "https://attack.mitre.org/techniques/T1218/"
    },

    # ── Lateral Movement ──────────────────────────────────────────────────
    "T1021": {
        "id": "T1021", "name": "Remote Services",
        "tactic": "Lateral Movement", "tactic_id": "TA0008",
        "description": "Using remote services to move laterally.",
        "url": "https://attack.mitre.org/techniques/T1021/"
    },

    # ── Collection ────────────────────────────────────────────────────────
    "T1113": {
        "id": "T1113", "name": "Screen Capture",
        "tactic": "Collection", "tactic_id": "TA0009",
        "description": "Capturing screen content to steal information.",
        "url": "https://attack.mitre.org/techniques/T1113/"
    },
}

# ══════════════════════════════════════════════════════════════════════════
#  MAPPING RULES
#  PE import name / string / YARA tag → list of technique IDs
# ══════════════════════════════════════════════════════════════════════════
IMPORT_TO_TECHNIQUES = {
    # Process injection
    "VirtualAllocEx":          ["T1055", "T1055.002"],
    "WriteProcessMemory":      ["T1055", "T1055.001"],
    "CreateRemoteThread":      ["T1055", "T1055.003"],
    "NtUnmapViewOfSection":    ["T1055", "T1055.012"],
    "ZwUnmapViewOfSection":    ["T1055", "T1055.012"],
    "RtlCreateUserThread":     ["T1055", "T1055.003"],
    "QueueUserAPC":            ["T1055"],
    # Anti-debug / evasion
    "IsDebuggerPresent":       ["T1622"],
    "CheckRemoteDebuggerPresent": ["T1622"],
    "NtQueryInformationProcess":  ["T1622"],
    "GetTickCount":            ["T1622"],
    "QueryPerformanceCounter": ["T1622"],
    # Memory / shellcode
    "VirtualAlloc":            ["T1620"],
    "VirtualProtect":          ["T1055", "T1620"],
    # Token manipulation
    "AdjustTokenPrivileges":   ["T1134"],
    "LookupPrivilegeValue":    ["T1134"],
    "ImpersonateLoggedOnUser": ["T1134", "T1134.001"],
    # Persistence — registry
    "RegSetValueExA":          ["T1547.001"],
    "RegSetValueExW":          ["T1547.001"],
    "RegCreateKeyExA":         ["T1547.001"],
    "RegCreateKeyExW":         ["T1547.001"],
    # Persistence — services
    "CreateServiceA":          ["T1543.003"],
    "CreateServiceW":          ["T1543.003"],
    "StartServiceA":           ["T1543.003"],
    # Network / C2
    "URLDownloadToFileA":      ["T1071.001"],
    "URLDownloadToFileW":      ["T1071.001"],
    "InternetOpenA":           ["T1071.001"],
    "InternetOpenUrlA":        ["T1071.001"],
    "WinHttpOpen":             ["T1071.001"],
    "WSAStartup":              ["T1095"],
    "socket":                  ["T1095"],
    # Crypto / ransomware
    "CryptEncrypt":            ["T1486"],
    "CryptGenKey":             ["T1486"],
    "BCryptEncrypt":           ["T1486"],
    # Keylogging
    "SetWindowsHookExA":       ["T1056.001"],
    "SetWindowsHookExW":       ["T1056.001"],
    "GetAsyncKeyState":        ["T1056.001"],
    # Execution
    "WinExec":                 ["T1106"],
    "ShellExecuteA":           ["T1106"],
    "ShellExecuteW":           ["T1106"],
    "CreateProcessA":          ["T1106"],
    "CreateProcessW":          ["T1106"],
    # Screen capture
    "BitBlt":                  ["T1113"],
    "GetDC":                   ["T1113"],
}

STRING_TO_TECHNIQUES = {
    "powershell":    ["T1059.001"],
    "cmd.exe":       ["T1059.003"],
    "schtasks":      ["T1053.005"],
    "mimikatz":      ["T1003"],
    "meterpreter":   ["T1219"],
    "cobalt strike": ["T1219"],
    "beacon":        ["T1219"],
    "vssadmin":      ["T1490"],
    "shadowcopy":    ["T1490"],
    "netsh":         ["T1021"],
}

PACKER_TO_TECHNIQUES = {
    "UPX":                 ["T1027.002"],
    "VMProtect":           ["T1027.002"],
    "Themida":             ["T1027.002"],
    "Themida/WinLicense":  ["T1027.002"],
    "MPRESS":              ["T1027.002"],
    "ASPack":              ["T1027.002"],
    "NsPack":              ["T1027.002"],
    "Petite":              ["T1027.002"],
    "Generic Packer":      ["T1027.002"],
}

YARA_TAG_TO_TECHNIQUES = {
    "injection":      ["T1055"],
    "process_hollow": ["T1055.012"],
    "ransomware":     ["T1486"],
    "keylogger":      ["T1056.001"],
    "rat":            ["T1219"],
    "persistence":    ["T1547.001"],
    "anti_debug":     ["T1622"],
    "anti_vm":        ["T1622"],
    "packer":         ["T1027.002"],
    "obfuscation":    ["T1027"],
    "shellcode":      ["T1620"],
    "credential":     ["T1003"],
    "network":        ["T1071.001"],
    "c2":             ["T1219"],
    "amsi_bypass":    ["T1562.001"],
    "privilege":      ["T1134"],
    "powershell":     ["T1059.001"],
    "cmd":            ["T1059.003"],
    "service":        ["T1543.003"],
    "screenshot":     ["T1113"],
}


# ══════════════════════════════════════════════════════════════════════════
#  MAIN MAPPER
# ══════════════════════════════════════════════════════════════════════════
def map_to_mitre(pe_result: dict = None,
                 yara_result: dict = None,
                 static_result: dict = None,
                 vt_mitre: list = None) -> dict:
    """
    Map scan results to MITRE ATT&CK techniques.

    Args:
        pe_result:    output of analyze_pe()
        yara_result:  output of scan_with_yara()
        static_result: output of analyze_file()
        vt_mitre:     list of MITRE strings from VT behavior (already parsed)

    Returns dict with:
        techniques: list of matched technique objects
        tactic_summary: dict of tactic → count
        total: int
    """
    seen_ids = set()
    matched  = []

    def _add(tech_ids: list, source: str):
        for tid in tech_ids:
            if tid in seen_ids: continue
            if tid not in TECHNIQUES: continue
            seen_ids.add(tid)
            t = dict(TECHNIQUES[tid])
            t["source"] = source
            matched.append(t)

    # ── From PE suspicious imports ────────────────────────────────────────
    if pe_result and pe_result.get("status") == "analyzed":
        for si in (pe_result.get("suspicious_imports") or []):
            fname = si.get("function") or si.get("name") or ""
            if fname in IMPORT_TO_TECHNIQUES:
                _add(IMPORT_TO_TECHNIQUES[fname], f"PE Import: {fname}")

        for packer in (pe_result.get("packers") or []):
            if packer in PACKER_TO_TECHNIQUES:
                _add(PACKER_TO_TECHNIQUES[packer], f"Packer: {packer}")

    # ── From YARA matches ─────────────────────────────────────────────────
    if yara_result:
        for match in (yara_result.get("matches") or []):
            if not isinstance(match, dict): continue
            rule = (match.get("rule") or "").lower()
            tags = [t.lower() for t in (match.get("tags") or [])]
            desc = (match.get("description") or "").lower()

            # Map by tags
            for tag in tags:
                if tag in YARA_TAG_TO_TECHNIQUES:
                    _add(YARA_TAG_TO_TECHNIQUES[tag], f"YARA: {match.get('rule','')}")

            # Map by rule name keywords
            for keyword, tech_ids in YARA_TAG_TO_TECHNIQUES.items():
                if keyword in rule or keyword in desc:
                    _add(tech_ids, f"YARA: {match.get('rule','')}")

    # ── From static analysis strings ──────────────────────────────────────
    if static_result:
        flags_text = " ".join(static_result.get("flags") or []).lower()
        for keyword, tech_ids in STRING_TO_TECHNIQUES.items():
            if keyword in flags_text:
                _add(tech_ids, f"String: {keyword}")

        # Also check suspicious_strings if present
        for s in (static_result.get("details", {}).get("suspicious_strings") or []):
            s_lower = s.lower()
            for keyword, tech_ids in STRING_TO_TECHNIQUES.items():
                if keyword in s_lower:
                    _add(tech_ids, f"String: {s}")

    # ── From VT behavior (already parsed strings like "T1055 Process Injection") ──
    if vt_mitre:
        for entry in vt_mitre:
            if not entry: continue
            parts = entry.strip().split(" ", 1)
            tid = parts[0].strip()
            if tid in TECHNIQUES and tid not in seen_ids:
                seen_ids.add(tid)
                t = dict(TECHNIQUES[tid])
                t["source"] = "VirusTotal Sandbox"
                matched.append(t)

    # ── Build tactic summary ──────────────────────────────────────────────
    tactic_summary = {}
    for t in matched:
        tac = t["tactic"]
        tactic_summary[tac] = tactic_summary.get(tac, 0) + 1

    return {
        "techniques":      matched,
        "tactic_summary":  tactic_summary,
        "total":           len(matched),
        "has_critical":    any(
            t["id"] in ["T1055","T1055.003","T1055.012","T1486","T1003"]
            for t in matched
        ),
    }