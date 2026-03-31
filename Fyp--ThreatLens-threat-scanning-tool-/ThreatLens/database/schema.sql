CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    scan_type TEXT NOT NULL,
    target TEXT,
    filename TEXT,
    file_size INTEGER,
    verdict TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    threat_score INTEGER DEFAULT 0,
    sha256 TEXT,
    md5 TEXT,
    result_json TEXT,
    scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS malware_hashes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256 TEXT UNIQUE NOT NULL,
    md5 TEXT,
    sha1 TEXT,
    malware_family TEXT,
    malware_type TEXT,
    tags TEXT,
    source TEXT DEFAULT 'MalwareBazaar',
    first_seen TEXT,
    added_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_malware_sha256 ON malware_hashes(sha256);
CREATE INDEX IF NOT EXISTS idx_malware_md5 ON malware_hashes(md5);
