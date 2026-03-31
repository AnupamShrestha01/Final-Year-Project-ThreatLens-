"""
backend/routes/chat_routes.py
Chatbot endpoint — powered by Ollama (offline LLM).
POST /chat/ask  { "message": "...", "context": {...} }
"""
import os
import requests
from flask import Blueprint, request, jsonify
from dotenv import load_dotenv

load_dotenv()

chat_bp = Blueprint("chat", __name__)

OLLAMA_URL   = os.getenv("OLLAMA_URL",   "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")

# 🧠 Simple in-memory chat history (per session can be improved later)
CHAT_MEMORY = []

SYSTEM_PROMPT = """You are ThreatLens AI, a cybersecurity assistant embedded inside a threat intelligence platform.
Your ONLY job is to help users understand their scan results.

Rules:
- Only answer questions about the scan result provided in the context.
- If asked something unrelated to the scan or cybersecurity, politely decline.
- Be concise, clear, and use simple language — users may not be security experts.
- When explaining verdicts, always mention what it means practically (e.g. "this file is dangerous and should be deleted").
- Format responses in short paragraphs. Do NOT use markdown headers or bullet points.
- Never reveal that you are powered by Ollama or any underlying model.
- You are ThreatLens AI. That is your only identity.
"""

def _build_context_summary(ctx: dict) -> str:
    if not ctx:
        return "No scan result available."

    lines = []
    scan_type = ctx.get("scan_type", "unknown")
    lines.append(f"Scan Type: {scan_type.upper()}")

    # Common fields
    for key, label in [
        ("input",          "Input"),
        ("hash_type",      "Hash Type"),
        ("verdict",        "Verdict"),
        ("risk",           "Risk Level"),
        ("threat_score",   "Threat Score"),
        ("threat_type",    "Threat Type"),
        ("malware_family", "Malware Family"),
        ("filename",       "File Name"),
        ("file_size",      "File Size"),
        ("url",            "URL"),
    ]:
        val = ctx.get(key)
        if val and val != "Unknown":
            lines.append(f"{label}: {val}")

    # Flags
    flags = ctx.get("flags", [])
    if flags:
        lines.append("Detection Flags: " + " | ".join(flags))

    # MITRE techniques
    mitre = ctx.get("mitre_techniques", [])
    if mitre:
        techs = ", ".join(f"{t['technique_id']} ({t['technique_name']})" for t in mitre[:5])
        lines.append(f"MITRE ATT&CK Techniques: {techs}")

    # Engine summaries
    engines = ctx.get("engines", {})
    eng_lines = []

    vt = engines.get("virustotal", {})
    if vt.get("status") == "found":
        eng_lines.append(f"VirusTotal: {vt.get('malicious', 0)}/{vt.get('total_engines', 0)} engines malicious")

    local = engines.get("local_db", {})
    if local.get("status") == "found":
        eng_lines.append(f"Local DB: Blacklisted — {local.get('malware_family', 'Unknown')}")

    otx = engines.get("otx", {})
    if otx.get("pulse_count", 0) > 0:
        eng_lines.append(f"OTX: Found in {otx['pulse_count']} threat pulse(s)")

    circl = engines.get("circl", {})
    if circl.get("status") == "found" and circl.get("known_good"):
        eng_lines.append(f"CIRCL: Known-good file (trust score {circl.get('trust_score', 0)}/100)")

    md = engines.get("metadefender", {})
    if md.get("status") == "found":
        eng_lines.append(f"MetaDefender: {md.get('malicious', 0)}/{md.get('total_engines', 0)} AV engines detected")

    if eng_lines:
        lines.append("Engine Results: " + " | ".join(eng_lines))

    # 🔥 Dynamic behavior results (file sandbox)
    dynamic = ctx.get("dynamic_behavior", {})
    if dynamic.get("threat_level"):
        lines.append(f"Docker Sandbox Result: {dynamic.get('threat_level')} (score {dynamic.get('threat_score', 0)})")
        if dynamic.get("suspicious_indicators"):
            lines.append("Sandbox Indicators: " + " | ".join(dynamic["suspicious_indicators"][:5]))
        if dynamic.get("mitre_tags"):
            tags = ", ".join(f"{t['id']} ({t['name']})" for t in dynamic["mitre_tags"][:5])
            lines.append(f"Sandbox MITRE Techniques: {tags}")

    # 🌐 Recon results (URL)
    recon = ctx.get("recon", {})
    if recon.get("threat_level"):
        lines.append(f"Recon Result: {recon.get('threat_level')} (score {recon.get('threat_score', 0)})")
        if recon.get("open_ports"):
            lines.append("Open Ports: " + ", ".join(recon["open_ports"][:10]))
        if recon.get("flags"):
            lines.append("Recon Flags: " + " | ".join(recon["flags"][:5]))

    # 🌍 URL browser analysis
    url_beh = ctx.get("url_behavior", {})
    if url_beh.get("threat_level"):
        lines.append(f"Browser Analysis Result: {url_beh.get('threat_level')} (score {url_beh.get('threat_score', 0)})")
        if url_beh.get("suspicious_indicators"):
            lines.append("Browser Indicators: " + " | ".join(url_beh["suspicious_indicators"][:5]))
        if url_beh.get("redirects"):
            lines.append(f"Redirects detected: {url_beh['redirects']}")
        if url_beh.get("forms_count"):
            lines.append(f"Forms found: {url_beh['forms_count']}")

    return "\n".join(lines)


@chat_bp.route("/ask", methods=["POST"])
def ask():
    global CHAT_MEMORY

    body    = request.get_json() or {}
    message = (body.get("message") or "").strip()
    context = body.get("context") or {}

    if not message:
        return jsonify({"success": False, "message": "No message provided."}), 400

    # limit message length (basic protection)
    message = message[:500]

    context_summary = _build_context_summary(context)

    # 🧠 include last 3 messages
    history_text = ""
    for item in CHAT_MEMORY[-3:]:
        history_text += f"User: {item['user']}\nAI: {item['ai']}\n"

    full_prompt = (
        f"{history_text}\n"
        f"Here is the current scan result the user is viewing:\n\n"
        f"{context_summary}\n\n"
        f"User question: {message}"
    )

    try:
        resp = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={
                "model":  OLLAMA_MODEL,
                "system": SYSTEM_PROMPT,
                "prompt": full_prompt,
                "stream": False,
                "options": {
                    "temperature": 0.3,
                    "num_predict": 400,
                }
            },
            timeout=20
        )

        if resp.status_code != 200:
            return jsonify({
                "success": False,
                "message": f"Ollama returned HTTP {resp.status_code}. Is Ollama running?"
            }), 502

        data  = resp.json()
        reply = data.get("response", "").strip()

        if not reply:
            return jsonify({"success": False, "message": "Empty response from model."}), 502

        # 🧠 save to memory
        CHAT_MEMORY.append({
            "user": message,
            "ai": reply
        })

        # keep only last 5 conversations
        CHAT_MEMORY = CHAT_MEMORY[-5:]

        return jsonify({"success": True, "reply": reply})

    except requests.exceptions.ConnectionError:
        return jsonify({
            "success": False,
            "message": "Cannot connect to Ollama. Make sure it is running: ollama serve"
        }), 503
    except requests.exceptions.Timeout:
        return jsonify({
            "success": False,
            "message": "Ollama took too long to respond. Try a shorter question."
        }), 504
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500