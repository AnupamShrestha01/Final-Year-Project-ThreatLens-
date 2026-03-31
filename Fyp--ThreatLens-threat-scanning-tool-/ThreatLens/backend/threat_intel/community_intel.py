"""
backend/threat_intel/community_intel.py

Community Threat Intelligence Engine
=====================================
Aggregates threat signals from the platform's own scan history.
When multiple independent users flag the same target as malicious,
confidence increases significantly — similar to how VirusTotal
uses community submissions to improve detection rates.

Logic:
- 2+ distinct users flagging same target as Malicious  → strong signal
- 1 user flagging as Malicious + high threat score     → moderate signal
- Multiple submissions as Suspicious                   → weak signal
- Clean submissions are ignored (no false positive risk)

Works for: URL, domain, IP, hash (MD5/SHA1/SHA256), filename
"""
import os
import sqlite3
import json
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "../../database/threatlens.db")


def _get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_community_table():
    """Create community_intel table if it doesn't exist."""
    try:
        conn = _get_conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS community_intel (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                target           TEXT NOT NULL,
                target_type      TEXT NOT NULL,
                verdict          TEXT DEFAULT 'Clean',
                submission_count INTEGER DEFAULT 1,
                malicious_count  INTEGER DEFAULT 0,
                suspicious_count INTEGER DEFAULT 0,
                clean_count      INTEGER DEFAULT 0,
                user_count       INTEGER DEFAULT 1,
                avg_threat_score REAL    DEFAULT 0.0,
                max_threat_score INTEGER DEFAULT 0,
                first_seen       DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen        DATETIME DEFAULT CURRENT_TIMESTAMP,
                tags             TEXT DEFAULT '[]',
                UNIQUE(target, target_type)
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_community_target
            ON community_intel(target)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_community_type
            ON community_intel(target_type)
        """)
        conn.commit()
        conn.close()
    except Exception:
        pass


def update_community_intel(
    target: str,
    target_type: str,
    verdict: str,
    threat_score: int,
    user_id: int,
    tags: list = None
):
    """
    Called after every scan to update community intelligence.
    Only malicious/suspicious verdicts contribute to threat signals.
    Clean scans update submission counts only.
    """
    if not target or not target_type:
        return

    ensure_community_table()
    target = target.strip().lower()
    verdict_map = {"Malicious": 3, "Suspicious": 2, "Clean": 1, "Invalid": 0}

    try:
        conn = _get_conn()

        existing = conn.execute(
            "SELECT * FROM community_intel WHERE target = ? AND target_type = ?",
            (target, target_type)
        ).fetchone()

        now = datetime.utcnow().isoformat()

        if existing:
            # Update existing record
            new_sub_count  = existing["submission_count"] + 1
            new_mal_count  = existing["malicious_count"]  + (1 if verdict == "Malicious"  else 0)
            new_sus_count  = existing["suspicious_count"] + (1 if verdict == "Suspicious" else 0)
            new_cln_count  = existing["clean_count"]      + (1 if verdict == "Clean"      else 0)

            # User count — check if this user has submitted before
            # We approximate by checking scan_history for distinct users
            user_count_row = conn.execute(
                """SELECT COUNT(DISTINCT user_id) as uc
                   FROM scan_history
                   WHERE (target = ? OR sha256 = ? OR md5 = ?)
                   AND verdict IN ('Malicious', 'Suspicious')""",
                (target, target, target)
            ).fetchone()
            new_user_count = max(
                existing["user_count"],
                user_count_row["uc"] if user_count_row else existing["user_count"]
            )

            # Running average threat score
            new_avg = (
                (existing["avg_threat_score"] * existing["submission_count"] + threat_score)
                / new_sub_count
            )
            new_max = max(existing["max_threat_score"], threat_score)

            # Highest verdict seen wins
            existing_priority = verdict_map.get(existing["verdict"], 0)
            new_priority      = verdict_map.get(verdict, 0)
            best_verdict = verdict if new_priority > existing_priority else existing["verdict"]

            # Merge tags
            try:
                existing_tags = json.loads(existing["tags"] or "[]")
            except Exception:
                existing_tags = []
            merged_tags = list(set(existing_tags + (tags or [])))[:20]

            conn.execute("""
                UPDATE community_intel SET
                    verdict          = ?,
                    submission_count = ?,
                    malicious_count  = ?,
                    suspicious_count = ?,
                    clean_count      = ?,
                    user_count       = ?,
                    avg_threat_score = ?,
                    max_threat_score = ?,
                    last_seen        = ?,
                    tags             = ?
                WHERE target = ? AND target_type = ?
            """, (
                best_verdict, new_sub_count, new_mal_count,
                new_sus_count, new_cln_count, new_user_count,
                round(new_avg, 2), new_max, now,
                json.dumps(merged_tags),
                target, target_type
            ))

        else:
            # Insert new record
            conn.execute("""
                INSERT INTO community_intel
                    (target, target_type, verdict, submission_count,
                     malicious_count, suspicious_count, clean_count,
                     user_count, avg_threat_score, max_threat_score,
                     first_seen, last_seen, tags)
                VALUES (?, ?, ?, 1, ?, ?, ?, 1, ?, ?, ?, ?, ?)
            """, (
                target, target_type, verdict,
                1 if verdict == "Malicious"  else 0,
                1 if verdict == "Suspicious" else 0,
                1 if verdict == "Clean"      else 0,
                float(threat_score), threat_score,
                now, now,
                json.dumps(tags or [])
            ))

        conn.commit()
        conn.close()

    except Exception:
        pass


def lookup_community_intel(target: str, target_type: str, current_user_id: int = None) -> dict:
    """
    Look up community threat intelligence for a target.

    Returns a dict with:
    - status: 'found' | 'not_found' | 'unavailable'
    - confidence: 'High' | 'Medium' | 'Low'
    - community_verdict: the aggregated verdict
    - submission_count: total times scanned on platform
    - malicious_count: times flagged malicious
    - user_count: distinct users who scanned it
    - avg_threat_score: average score across all scans
    - max_threat_score: highest score ever seen
    - signal_score: 0-100 threat signal for scoring engine
    - first_seen / last_seen: timestamps
    """
    if not target or not target_type:
        return {"engine": "Community Intel", "status": "unavailable"}

    ensure_community_table()
    target = target.strip().lower()

    try:
        conn = _get_conn()
        row = conn.execute(
            "SELECT * FROM community_intel WHERE target = ? AND target_type = ?",
            (target, target_type)
        ).fetchone()
        conn.close()

        if not row:
            return {"engine": "Community Intel", "status": "not_found",
                    "verdict": "Clean", "signal_score": 0}

        sub_count  = row["submission_count"] or 0
        mal_count  = row["malicious_count"]  or 0
        sus_count  = row["suspicious_count"] or 0
        user_count = row["user_count"]       or 1
        avg_score  = row["avg_threat_score"] or 0.0
        max_score  = row["max_threat_score"] or 0

        # ── Signal calculation ────────────────────────────────────────────
        # Base signal from malicious ratio
        if sub_count > 0:
            mal_ratio = mal_count / sub_count
        else:
            mal_ratio = 0.0

        # User diversity multiplier — more distinct users = higher confidence
        # 1 user = 0.5x, 2 users = 0.75x, 3+ users = 1.0x
        if user_count >= 3:
            diversity_mult = 1.0
        elif user_count == 2:
            diversity_mult = 0.75
        else:
            diversity_mult = 0.50

        # Raw signal: malicious ratio × diversity × average score
        raw_signal = mal_ratio * diversity_mult * avg_score

        # Boost for multiple independent malicious flags
        if mal_count >= 5 and user_count >= 3:
            raw_signal = max(raw_signal, 75)
        elif mal_count >= 3 and user_count >= 2:
            raw_signal = max(raw_signal, 55)
        elif mal_count >= 2 and user_count >= 2:
            raw_signal = max(raw_signal, 40)
        elif mal_count >= 1:
            raw_signal = max(raw_signal, 20)

        # Suspicious submissions add a smaller signal
        if sus_count >= 3:
            raw_signal = max(raw_signal, 25)
        elif sus_count >= 1 and mal_count == 0:
            raw_signal = max(raw_signal, 10)

        signal_score = min(int(round(raw_signal)), 100)

        # ── Confidence level ──────────────────────────────────────────────
        if user_count >= 3 and mal_count >= 3:
            confidence = "High"
        elif user_count >= 2 and mal_count >= 1:
            confidence = "Medium"
        elif mal_count >= 1:
            confidence = "Low"
        else:
            confidence = "None"

        # ── Community verdict ─────────────────────────────────────────────
        if mal_count >= 2 or (mal_count >= 1 and user_count >= 2):
            community_verdict = "Malicious"
        elif mal_count >= 1 or sus_count >= 3:
            community_verdict = "Suspicious"
        elif sus_count >= 1:
            community_verdict = "Suspicious"
        else:
            community_verdict = "Clean"

        try:
            tags = json.loads(row["tags"] or "[]")
        except Exception:
            tags = []

        return {
            "engine":            "Community Intel",
            "status":            "found",
            "verdict":           community_verdict,
            "confidence":        confidence,
            "signal_score":      signal_score,
            "submission_count":  sub_count,
            "malicious_count":   mal_count,
            "suspicious_count":  sus_count,
            "clean_count":       row["clean_count"] or 0,
            "user_count":        user_count,
            "avg_threat_score":  round(avg_score, 1),
            "max_threat_score":  max_score,
            "first_seen":        row["first_seen"],
            "last_seen":         row["last_seen"],
            "tags":              tags,
        }

    except Exception as e:
        return {"engine": "Community Intel", "status": "unavailable", "error": str(e)}


def get_community_stats() -> dict:
    """Get overall community intelligence statistics."""
    ensure_community_table()
    try:
        conn = _get_conn()
        total     = conn.execute("SELECT COUNT(*) as c FROM community_intel").fetchone()["c"]
        malicious = conn.execute(
            "SELECT COUNT(*) as c FROM community_intel WHERE malicious_count > 0"
        ).fetchone()["c"]
        top = conn.execute("""
            SELECT target, target_type, malicious_count, user_count, avg_threat_score
            FROM community_intel
            WHERE malicious_count > 0
            ORDER BY malicious_count DESC, user_count DESC
            LIMIT 10
        """).fetchall()
        conn.close()
        return {
            "total_entries":    total,
            "malicious_entries": malicious,
            "top_threats":      [dict(r) for r in top]
        }
    except Exception as e:
        return {"error": str(e)}