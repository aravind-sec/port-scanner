from flask import Flask, request, render_template, jsonify
import socket
import subprocess
import threading
import json
import re
import os
import datetime

app = Flask(__name__)

# ── helpers ──────────────────────────────────────────────────────────────────

def resolve_ip(target):
    try:
        return socket.gethostbyname(target)
    except Exception as e:
        return str(e)

def run_cmd(cmd, timeout=60):
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True,
            text=True, timeout=timeout
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "[TIMEOUT] Command took too long."
    except Exception as e:
        return f"[ERROR] {str(e)}"

# ── scanners ──────────────────────────────────────────────────────────────────

def run_nmap(target):
    output = run_cmd(f"nmap -sV -sC --open -p 1-1000 --host-timeout 60s {target}", timeout=90)
    ports = []
    services = []
    for line in output.splitlines():
        m = re.match(r'(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)', line)
        if m:
            ports.append(int(m.group(1)))
            services.append({
                "port": int(m.group(1)),
                "proto": m.group(2),
                "service": m.group(3),
                "version": m.group(4).strip()
            })
    return {"raw": output, "open_ports": ports, "services": services}

def run_nikto(target):
    output = run_cmd(f"nikto -h http://{target} -maxtime 60s -nointeractive", timeout=90)
    findings = []
    for line in output.splitlines():
        if line.startswith("+ ") and "OSVDB" not in line and "Server:" not in line:
            findings.append(line[2:].strip())
    return {"raw": output, "findings": findings[:20]}  # cap at 20

def run_whatweb(target):
    output = run_cmd(f"whatweb --color=never {target}", timeout=30)
    techs = []
    m = re.search(r'http[s]?://\S+\s+\[.*?\]\s+(.*)', output)
    if m:
        raw_techs = m.group(1)
        techs = [t.strip() for t in raw_techs.split(',') if t.strip()]
    return {"raw": output, "technologies": techs}

def run_whois(target):
    output = run_cmd(f"whois {target}", timeout=20)
    info = {}
    for key, pattern in [
        ("registrar", r'Registrar:\s*(.+)'),
        ("creation", r'Creation Date:\s*(.+)'),
        ("expiry",   r'Registry Expiry Date:\s*(.+)'),
        ("org",      r'Registrant Organization:\s*(.+)'),
        ("country",  r'Registrant Country:\s*(.+)'),
    ]:
        m = re.search(pattern, output, re.IGNORECASE)
        if m:
            info[key] = m.group(1).strip()
    return {"raw": output, "info": info}

# ── scoring ───────────────────────────────────────────────────────────────────

RISKY_PORTS   = {21, 23, 25, 110, 135, 137, 139, 445, 1433, 3306, 3389, 5900}
CRITICAL_PORTS = {23, 445, 3389, 5900}

RISKY_KEYWORDS = [
    "sql injection", "xss", "csrf", "directory traversal",
    "remote file", "disclosure", "default credential",
    "outdated", "vulnerable", "backdoor", "misconfigured"
]

def calculate_score(nmap_data, nikto_data, whatweb_data):
    score = 0.0
    reasons = []

    open_ports = set(nmap_data.get("open_ports", []))

    # Critical ports open → +2
    crit = open_ports & CRITICAL_PORTS
    if crit:
        score += 2.0
        reasons.append(f"Critical ports open: {sorted(crit)}")

    # Risky ports open → +1
    risky = (open_ports & RISKY_PORTS) - CRITICAL_PORTS
    if risky:
        score += 1.0
        reasons.append(f"Risky ports open: {sorted(risky)}")

    # Many open ports → +0.5
    if len(open_ports) > 10:
        score += 0.5
        reasons.append(f"{len(open_ports)} ports open (large attack surface)")

    # Nikto findings
    findings = nikto_data.get("findings", [])
    critical_findings = [f for f in findings if any(k in f.lower() for k in RISKY_KEYWORDS)]
    if critical_findings:
        score += min(len(critical_findings) * 0.5, 2.0)
        reasons.append(f"{len(critical_findings)} critical web vulnerability(ies) found")
    elif findings:
        score += 0.5
        reasons.append(f"{len(findings)} informational web finding(s)")

    score = round(min(score, 5.0), 1)

    if score == 0:
        level = "SECURE"
        color = "#00ff9d"
    elif score <= 1:
        level = "LOW RISK"
        color = "#a8ff78"
    elif score <= 2:
        level = "MODERATE"
        color = "#ffdd57"
    elif score <= 3.5:
        level = "HIGH RISK"
        color = "#ff9933"
    else:
        level = "CRITICAL"
        color = "#ff3c5a"

    return {"score": score, "level": level, "color": color, "reasons": reasons}

# ── routes ────────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "No target provided"}), 400

    ip = resolve_ip(target)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Run all scanners
    nmap_data    = run_nmap(ip)
    nikto_data   = run_nikto(target)
    whatweb_data = run_whatweb(target)
    whois_data   = run_whois(target)
    scoring      = calculate_score(nmap_data, nikto_data, whatweb_data)

    return jsonify({
        "target":     target,
        "ip":         ip,
        "timestamp":  timestamp,
        "nmap":       nmap_data,
        "nikto":      nikto_data,
        "whatweb":    whatweb_data,
        "whois":      whois_data,
        "score":      scoring,
    })

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
