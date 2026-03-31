# Maps malware family names → MITRE ATT&CK techniques
# Based on common malware families and their known TTPs

FAMILY_MITRE_MAP = {
    "agenttesla":   [("T1566", "Phishing"), ("T1055", "Process Injection"), ("T1082", "System Info Discovery"), ("T1005", "Data from Local System")],
    "emotet":       [("T1566", "Phishing"), ("T1027", "Obfuscated Files"), ("T1059", "Command & Scripting"), ("T1078", "Valid Accounts")],
    "wannacry":     [("T1486", "Data Encrypted for Impact"), ("T1210", "Exploit Public-Facing App"), ("T1071", "App Layer Protocol")],
    "mirai":        [("T1190", "Exploit Public-Facing App"), ("T1498", "Network DoS"), ("T1110", "Brute Force")],
    "remcos":       [("T1055", "Process Injection"), ("T1059", "Command & Scripting"), ("T1113", "Screen Capture"), ("T1056", "Input Capture")],
    "njrat":        [("T1055", "Process Injection"), ("T1056", "Input Capture"), ("T1113", "Screen Capture"), ("T1041", "Exfiltration Over C2")],
    "formbook":     [("T1056", "Input Capture"), ("T1113", "Screen Capture"), ("T1005", "Data from Local System")],
    "lokibot":      [("T1555", "Credentials from Password Stores"), ("T1056", "Input Capture"), ("T1041", "Exfiltration Over C2")],
    "asyncrat":     [("T1059", "Command & Scripting"), ("T1055", "Process Injection"), ("T1083", "File & Directory Discovery")],
    "redline":      [("T1555", "Credentials from Password Stores"), ("T1005", "Data from Local System"), ("T1041", "Exfiltration Over C2")],
    "raccoon":      [("T1555", "Credentials from Password Stores"), ("T1005", "Data from Local System")],
    "nanocore":     [("T1055", "Process Injection"), ("T1056", "Input Capture"), ("T1113", "Screen Capture")],
    "quakbot":      [("T1566", "Phishing"), ("T1055", "Process Injection"), ("T1082", "System Info Discovery")],
    "trickbot":     [("T1566", "Phishing"), ("T1027", "Obfuscated Files"), ("T1055", "Process Injection")],
    "darkcomet":    [("T1056", "Input Capture"), ("T1113", "Screen Capture"), ("T1041", "Exfiltration Over C2")],
    "ransomware":   [("T1486", "Data Encrypted for Impact"), ("T1490", "Inhibit System Recovery")],
    "trojan":       [("T1059", "Command & Scripting"), ("T1055", "Process Injection")],
    "spyware":      [("T1056", "Input Capture"), ("T1113", "Screen Capture")],
    "backdoor":     [("T1059", "Command & Scripting"), ("T1071", "App Layer Protocol")],
    "worm":         [("T1210", "Exploit Remote Services"), ("T1080", "Taint Shared Content")],
    "keylogger":    [("T1056", "Input Capture")],
    "miner":        [("T1496", "Resource Hijacking")],
    "adware":       [("T1176", "Browser Extensions")],
    "rootkit":      [("T1014", "Rootkit"), ("T1055", "Process Injection")],
    "botnet":       [("T1071", "App Layer Protocol"), ("T1498", "Network DoS")]
}

def map_mitre_from_family(family_name: str) -> list:
    """
    Given a malware family name, return matching MITRE ATT&CK techniques.
    Returns list of dicts with technique_id and technique_name.
    """
    if not family_name:
        return []

    family_lower = family_name.lower().replace(" ", "").replace("-", "").replace("_", "")

    techniques = []

    for keyword, techs in FAMILY_MITRE_MAP.items():
        if keyword in family_lower or family_lower in keyword:
            for tid, tname in techs:
                entry = {"technique_id": tid, "technique_name": tname}
                if entry not in techniques:
                    techniques.append(entry)

    return techniques


def map_mitre_from_tags(tags: list) -> list:
    """Also check tags list for family names."""
    techniques = []
    for tag in (tags or []):
        found = map_mitre_from_family(tag)
        for t in found:
            if t not in techniques:
                techniques.append(t)
    return techniques