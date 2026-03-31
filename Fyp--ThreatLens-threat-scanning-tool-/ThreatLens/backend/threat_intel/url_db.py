"""
backend/threat_intel/url_db.py
Local malicious URL/Domain database
Compatible with URLhaus CSV/TXT dumps (no header, positional columns)
"""
import os, sqlite3, csv, zipfile, tempfile
from urllib.parse import urlparse

DB_PATH   = os.path.join(os.path.dirname(__file__), "../../database/threatlens.db")
FEEDS_DIR = os.path.join(os.path.dirname(__file__), "../../database/url_feeds")


def _get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_table():
    try:
        conn = _get_conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS url_blacklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                domain TEXT,
                category TEXT,
                threat TEXT,
                source TEXT DEFAULT 'URLhaus',
                date_added TEXT,
                added_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_url_domain ON url_blacklist(domain)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_url_url ON url_blacklist(url)")
        conn.commit()
        conn.close()
    except Exception:
        pass


def lookup_url_db(url: str, domain: str = "") -> dict:
    """Check if URL or domain is in local blacklist."""
    _ensure_table()
    try:
        conn = _get_conn()
        row = None

        if url:
            clean_url = url.rstrip("/")
            # Try exact match, with slash, and LIKE prefix match
            row = conn.execute(
                """SELECT * FROM url_blacklist 
                   WHERE url = ? OR url = ? OR ? LIKE url || '%' OR url LIKE ? || '%'
                   LIMIT 1""",
                (clean_url, clean_url + "/", clean_url, clean_url)
            ).fetchone()

        if not row and domain:
            clean_domain = domain.split(":")[0]
            # Check exact domain first
            row = conn.execute(
                "SELECT * FROM url_blacklist WHERE domain = ? LIMIT 1",
                (clean_domain,)
            ).fetchone()

            # If not found, strip subdomains one level at a time
            if not row:
                parts = clean_domain.split(".")
                for i in range(1, len(parts) - 1):
                    parent = ".".join(parts[i:])
                    row = conn.execute(
                        "SELECT * FROM url_blacklist WHERE domain = ? LIMIT 1",
                        (parent,)
                    ).fetchone()
                    if row:
                        break

            # Also try LIKE match on domain
            if not row:
                row = conn.execute(
                    "SELECT * FROM url_blacklist WHERE domain LIKE ? LIMIT 1",
                    ("%" + clean_domain + "%",)
                ).fetchone()

        conn.close()

        if row:
            return {
                "engine":     "Local DB",
                "status":     "found",
                "verdict":    "Malicious",
                "category":   row["category"] or "malicious",
                "threat":     row["threat"] or "Known malicious URL",
                "source":     row["source"] or "Local DB",
                "url":        row["url"] or url,
                "domain":     row["domain"] or domain,
                "date_added": row["date_added"] or "",
            }
        return {"engine": "Local DB", "status": "not_found", "verdict": "Clean"}
    except Exception as e:
        return {"engine": "Local DB", "status": "unavailable", "error": str(e)}

def get_url_db_stats() -> dict:
    _ensure_table()
    try:
        conn = _get_conn()
        total = conn.execute("SELECT COUNT(*) as c FROM url_blacklist").fetchone()["c"]
        categories = conn.execute("""
            SELECT category, COUNT(*) as c FROM url_blacklist
            GROUP BY category ORDER BY c DESC LIMIT 10
        """).fetchall()
        conn.close()
        return {
            "total_urls": total,
            "categories": [{"category": r["category"], "count": r["c"]} for r in categories]
        }
    except Exception as e:
        return {"total_urls": 0, "categories": [], "error": str(e)}


def import_urlhaus_csv(filepath: str, source_name: str = "URLhaus") -> dict:
    """
    Import URLhaus dump — supports both formats:

    Format 1 (with header): id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
    Format 2 (no header):   same columns, positional
    Both CSV and TXT files supported.

    URLhaus column positions:
      0=id, 1=date, 2=url, 3=status, 4=last_online, 5=threat, 6=tags, 7=urlhaus_link, 8=reporter
    """
    entries = []
    errors  = 0

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        lines = content.splitlines()
        # Skip comment lines
        data_lines = [l for l in lines if l.strip() and not l.strip().startswith("#")]

        if not data_lines:
            return {"success": False, "error": "No data found in file"}

        first = data_lines[0].strip().strip('"')

        # Detect if first line is a header (contains 'url' or 'dateadded' as text)
        has_header = any(kw in first.lower() for kw in ["dateadded", "url_status", "urlhaus"])
        start_lines = data_lines[1:] if has_header else data_lines

        reader = csv.reader(iter(start_lines))
        for row in reader:
            try:
                # Strip quotes from all fields
                row = [c.strip().strip('"').strip("'").strip() for c in row]

                if len(row) < 3:
                    continue

                # URLhaus format: id(0), date(1), url(2), status(3), last_online(4), threat(5), tags(6)
                url = row[2] if len(row) > 2 else ""
                if not url or not url.startswith("http"):
                    # Try column 1 in case it's a different format
                    if len(row) > 1 and row[1].startswith("http"):
                        url = row[1]
                    else:
                        continue

                # Extract domain
                try:
                    domain = urlparse(url).netloc or ""
                except Exception:
                    domain = ""

                threat   = row[5] if len(row) > 5 else "malware"
                tags     = row[6] if len(row) > 6 else ""
                date_add = row[1][:10] if len(row) > 1 else ""

                entries.append({
                    "url":        url,
                    "domain":     domain,
                    "category":   threat or "malware",
                    "threat":     threat or "malicious",
                    "source":     source_name,
                    "date_added": date_add,
                })
            except Exception:
                errors += 1
                continue

        if not entries:
            return {"success": False, "error": "No valid URLs parsed from file"}

        _ensure_table()
        conn = _get_conn()
        conn.executemany("""
            INSERT OR IGNORE INTO url_blacklist
                (url, domain, category, threat, source, date_added)
            VALUES (:url, :domain, :category, :threat, :source, :date_added)
        """, entries)
        inserted = conn.total_changes
        conn.commit()
        conn.close()

        return {"success": True, "parsed": len(entries), "inserted": inserted, "errors": errors}

    except Exception as e:
        return {"success": False, "error": str(e)}


def import_url_feeds() -> dict:
    """Auto-import all CSV/TXT/ZIP files from database/url_feeds/ folder."""
    os.makedirs(FEEDS_DIR, exist_ok=True)
    _ensure_table()

    files = [f for f in os.listdir(FEEDS_DIR)
             if f.endswith((".csv", ".txt", ".zip")) and not f.startswith(".")]

    if not files:
        return {"success": False, "error": f"No feed files found in {FEEDS_DIR}"}

    total_inserted = 0
    results = []

    for fname in files:
        fpath = os.path.join(FEEDS_DIR, fname)
        if fname.endswith(".zip"):
            r = _import_zip(fpath, fname)
        else:
            r = import_urlhaus_csv(fpath, fname)
        r["file"] = fname
        results.append(r)
        total_inserted += r.get("inserted", 0)

    return {"success": True, "total_inserted": total_inserted, "files": results}


def _import_zip(filepath: str, source_name: str) -> dict:
    total_inserted = 0
    total_parsed   = 0
    files_done     = 0
    try:
        with zipfile.ZipFile(filepath, "r") as zf:
            for name in zf.namelist():
                # Accept .csv, .txt, and any file without extension that isn't a folder
                if name.endswith((".csv", ".txt")) or (
                    "." not in os.path.basename(name) and not name.endswith("/")):
                    with zf.open(name) as zf_file:
                        tmp = os.path.join(tempfile.gettempdir(), f"url_import_{files_done}.csv")
                        with open(tmp, "wb") as out:
                            out.write(zf_file.read())
                        r = import_urlhaus_csv(tmp, source_name)
                        if r.get("success"):
                            total_parsed   += r.get("parsed", 0)
                            total_inserted += r.get("inserted", 0)
                            files_done += 1
                        try:
                            os.remove(tmp)
                        except Exception:
                            pass
        return {"success": True, "parsed": total_parsed,
                "inserted": total_inserted, "files": files_done}
    except Exception as e:
        return {"success": False, "error": str(e)}