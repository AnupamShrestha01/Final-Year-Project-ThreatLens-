"""
backend/engines/yara_engine.py

Real yara-python engine with pure-Python fallback.
- If yara-python is installed: compiles and runs all .yar/.yara rules properly
- If not installed: falls back to the pure Python regex engine

Install real YARA:  pip install yara-python
Add rules:          drop .yar files into /yara_rules/ folder
"""

import os
import re
import glob

YARA_DIR = os.path.join(os.path.dirname(__file__), "../../yara_rules")

# ── Try importing real yara-python ────────────────────────────────────────
try:
    import yara as _yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


# ══════════════════════════════════════════════════════════════════
#  REAL yara-python ENGINE
# ══════════════════════════════════════════════════════════════════

def _scan_with_real_yara(file_data: bytes) -> dict:
    """Use real yara-python to compile and match all rules."""
    rules_dir = YARA_DIR
    compiled_rules = []
    load_errors = []

    for path in glob.glob(os.path.join(rules_dir, "**", "*.yar"), recursive=True) + \
                glob.glob(os.path.join(rules_dir, "**", "*.yara"), recursive=True):
        try:
            rule = _yara.compile(filepath=path)
            compiled_rules.append((os.path.basename(path), rule))
        except _yara.SyntaxError as e:
            load_errors.append(f"{os.path.basename(path)}: {str(e)[:60]}")
        except Exception as e:
            load_errors.append(f"{os.path.basename(path)}: {str(e)[:60]}")

    matches = []
    risk_score = 0

    for rulefile, rule in compiled_rules:
        try:
            hits = rule.match(data=file_data)
            for hit in hits:
                # Get severity from meta if present
                severity = "medium"
                description = hit.rule
                if hasattr(hit, "meta"):
                    severity    = hit.meta.get("severity", "medium").lower()
                    description = hit.meta.get("description", hit.rule)

                matches.append({
                    "rule":        hit.rule,
                    "description": description,
                    "severity":    severity,
                    "tags":        list(hit.tags) if hit.tags else [],
                    "source":      rulefile,
                })

                if severity in ("critical",): risk_score += 75
                elif severity == "high":       risk_score += 50
                elif severity == "medium":     risk_score += 25
                else:                          risk_score += 10

        except Exception:
            continue

    risk_score = min(risk_score, 100)

    if risk_score >= 50:   verdict = "Malicious"
    elif risk_score > 0:   verdict = "Suspicious"
    else:                  verdict = "Clean"

    return {
        "engine":        "YARA (yara-python)",
        "rules_loaded":  len(compiled_rules),
        "load_errors":   len(load_errors),
        "matches":       matches,
        "matched_count": len(matches),
        "risk_score":    risk_score,
        "verdict":       verdict,
    }


# ══════════════════════════════════════════════════════════════════
#  PURE PYTHON FALLBACK ENGINE
# ══════════════════════════════════════════════════════════════════

def _load_rules_fallback(rules_dir: str) -> list:
    rules = []
    for path in glob.glob(os.path.join(rules_dir, "*.yar")) + \
                glob.glob(os.path.join(rules_dir, "*.yara")):
        try:
            with open(path, "r", errors="replace") as f:
                content = f.read()

            for rule_match in re.finditer(r'rule\s+(\w+)\s*(?::\s*[\w\s]+)?\{(.*?)\}(?=\s*rule|\s*$)',
                                           content, re.DOTALL):
                rule_name = rule_match.group(1)
                rule_body = rule_match.group(2)

                desc_m = re.search(r'description\s*=\s*"([^"]+)"', rule_body)
                sev_m  = re.search(r'severity\s*=\s*"([^"]+)"',    rule_body)
                description = desc_m.group(1) if desc_m else rule_name
                severity    = sev_m.group(1).lower()  if sev_m  else "medium"

                patterns = []
                strings_section = re.search(r'strings:(.*?)condition:', rule_body, re.DOTALL)
                if strings_section:
                    for line in strings_section.group(1).splitlines():
                        line = line.strip()
                        if not line or line.startswith("//"):
                            continue

                        # Byte pattern { 4D 5A ... }
                        m = re.match(r'\$\w+\s*=\s*\{([0-9A-Fa-f\s\?\[\]\-]+)\}', line)
                        if m:
                            hex_str = re.sub(r'[^0-9A-Fa-f]', '', m.group(1))
                            if len(hex_str) >= 2:
                                patterns.append({"type": "bytes", "pattern": hex_str})
                            continue

                        # Regex /pattern/ nocase
                        m = re.match(r'\$\w+\s*=\s*/([^/]+)/(\s*nocase)?', line)
                        if m:
                            patterns.append({"type": "regex", "pattern": m.group(1),
                                             "nocase": bool(m.group(2))})
                            continue

                        # String "value" nocase
                        m = re.match(r'\$\w+\s*=\s*"([^"]+)"(\s*nocase)?', line)
                        if m:
                            patterns.append({"type": "string", "pattern": m.group(1),
                                             "nocase": bool(m.group(2))})

                condition_match = re.search(r'condition:(.*?)$', rule_body, re.DOTALL)
                condition_raw = condition_match.group(1).strip() if condition_match else ""

                if patterns:
                    rules.append({
                        "name":          rule_name,
                        "description":   description,
                        "severity":      severity,
                        "patterns":      patterns,
                        "condition_raw": condition_raw,
                        "source":        os.path.basename(path),
                    })

        except Exception:
            continue

    return rules


def _match_rule_fallback(rule: dict, data: bytes) -> bool:
    matched = []
    for p in rule["patterns"]:
        try:
            if p["type"] == "bytes":
                try:
                    byte_seq = bytes.fromhex(p["pattern"])
                    if byte_seq in data:
                        matched.append(p)
                except Exception:
                    pass

            elif p["type"] == "string":
                needle = p["pattern"].encode("utf-8", errors="replace")
                if p.get("nocase"):
                    if needle.lower() in data.lower():
                        matched.append(p)
                else:
                    if needle in data:
                        matched.append(p)

            elif p["type"] == "regex":
                text  = data.decode("utf-8", errors="ignore")
                flags = re.IGNORECASE if p.get("nocase") else 0
                if re.search(p["pattern"], text, flags):
                    matched.append(p)
        except Exception:
            continue

    total = len(rule["patterns"])
    count = len(matched)
    cond  = rule.get("condition_raw", "").lower()

    if not cond or count == 0:
        return count >= 1

    if "all of them" in cond:
        return count == total
    if "any of them" in cond:
        return count >= 1

    # X of them
    m = re.search(r'(\d+)\s+of\s+them', cond)
    if m:
        return count >= int(m.group(1))

    # X of ($prefix*)
    m = re.search(r'(\d+)\s+of\s+\(\$(\w+)\*\)', cond)
    if m:
        return count >= int(m.group(1))

    # any of ($prefix*)
    m = re.search(r'any\s+of\s+\(\$(\w+)\*\)', cond)
    if m:
        return count >= 1

    # $var at 0
    m = re.search(r'\$\w+\s+at\s+0', cond)
    if m:
        for p in rule["patterns"]:
            if p["type"] == "string" and data.startswith(p["pattern"].encode()):
                return True
            if p["type"] == "bytes":
                try:
                    if data.startswith(bytes.fromhex(p["pattern"])):
                        return True
                except Exception:
                    pass
        return False

    return count >= 1


def _scan_with_fallback(file_data: bytes) -> dict:
    rules   = _load_rules_fallback(YARA_DIR)
    matches = []
    risk_score = 0

    for rule in rules:
        if _match_rule_fallback(rule, file_data):
            matches.append({
                "rule":        rule["name"],
                "description": rule["description"],
                "severity":    rule["severity"],
                "tags":        [],
                "source":      rule.get("source", ""),
            })
            sev = rule["severity"]
            if sev == "critical": risk_score += 75
            elif sev == "high":   risk_score += 50
            elif sev == "medium": risk_score += 25
            else:                 risk_score += 10

    risk_score = min(risk_score, 100)
    if risk_score >= 50:  verdict = "Malicious"
    elif risk_score > 0:  verdict = "Suspicious"
    else:                 verdict = "Clean"

    return {
        "engine":        "YARA (Pure Python Fallback)",
        "rules_loaded":  len(rules),
        "load_errors":   0,
        "matches":       matches,
        "matched_count": len(matches),
        "risk_score":    risk_score,
        "verdict":       verdict,
    }


# ══════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ══════════════════════════════════════════════════════════════════

def scan_with_yara(file_data: bytes) -> dict:
    """
    Scan file_data against all YARA rules.
    Uses real yara-python if installed, otherwise pure Python fallback.
    """
    if YARA_AVAILABLE:
        return _scan_with_real_yara(file_data)
    else:
        return _scan_with_fallback(file_data)


def get_yara_status() -> dict:
    """Return info about YARA engine status — useful for admin dashboard."""
    rule_count = len(
        glob.glob(os.path.join(YARA_DIR, "**", "*.yar"),  recursive=True) +
        glob.glob(os.path.join(YARA_DIR, "**", "*.yara"), recursive=True)
    )
    return {
        "library":    "yara-python" if YARA_AVAILABLE else "Pure Python Fallback",
        "available":  YARA_AVAILABLE,
        "rules_dir":  YARA_DIR,
        "rule_files": rule_count,
    }