# ThreatLens

## How to Run

### 1. Start the Backend
```bash
cd ThreatLens
python3 backend/app.py
```
Runs at: http://127.0.0.1:5000

### 2. Open Frontend
Open frontend/pages/login.html via VS Code Live Server (port 5500)

### 3. Optional: Add VirusTotal API Key
Set environment variable: VT_API_KEY=your_key
Or edit .env/.env

## What's Working (Phase 1)
- User registration & login (SQLite DB with hashed passwords)
- File upload & scan with 3 engines:
  - Static Analysis (entropy, PE headers, suspicious strings)
  - YARA Rules (malware, ransomware, suspicious patterns)
  - VirusTotal API (when key configured)
- Per-user scan history saved to database
- Full result page with threat score, engine breakdown, YARA matches
