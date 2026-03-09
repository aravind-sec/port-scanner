from flask import Flask, request, render_template, jsonify
import socket
import subprocess
import threading
import re
import datetime

app = Flask(__name__)

# ── helpers ───────────────────────────────────────────────────────────────────

def resolve_ip(target):
    try:
        return socket.gethostbyname(target)
    except Exception as e:
        return str(e)

def run_cmd(cmd, timeout=180):
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        out = result.stdout + result.stderr
        return out if out.strip() else "[NO OUTPUT]"
    except subprocess.TimeoutExpired:
        return "[TIMEOUT] Scan exceeded time limit."
    except Exception as e:
        return f"[ERROR] {str(e)}"

# ── scanners ──────────────────────────────────────────────────────────────────

def run_nmap(ip):
    cmd = "nmap -sV -sC -O --open -p 1-1000 --host-timeout 150s --script=vuln " + ip
    output = run_cmd(cmd, timeout=180)
    ports, services = [], []
    for line in output.splitlines():
        m = re.match(r'(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)', line)
        if m:
            ports.append(int(m.group(1)))
            services.append({
                "port":    int(m.group(1)),
                "proto":   m.group(2),
                "service": m.group(3),
                "version": m.group(4).strip()
            })
    return {"raw": output, "open_ports": ports, "services": services}

def run_nikto(target):
    cmd = "nikto -h http://" + target + " -maxtime 150 -nointeractive -C all"
    output = run_cmd(cmd, timeout=180)
    findings = []
    for line in output.splitlines():
        if line.startswith("+ ") and "Server:" not in line:
            findings.append(line[2:].strip())
    return {"raw": output, "findings": findings[:30]}

def run_whatweb(target):
    cmd = "whatweb --color=never --aggression=3 " + target
    output = run_cmd(cmd, timeout=60)
    techs = []
    m = re.search(r'http[s]?://\S+\s+\[.*?\]\s+(.*)', output)
    if m:
        techs = [t.strip() for t in m.group(1).split(',') if t.strip()]
    return {"raw": output, "technologies": techs}

def run_whois(target):
    cmd = "whois " + target
    output = run_cmd(cmd, timeout=30)
    info = {}
    for key, pattern in [
        ("registrar",  r'Registrar:\s*(.+)'),
        ("creation",   r'Creation Date:\s*(.+)'),
        ("expiry",     r'Registry Expiry Date:\s*(.+)'),
        ("org",        r'Registrant Organization:\s*(.+)'),
        ("country",    r'Registrant Country:\s*(.+)'),
        ("nameserver", r'Name Server:\s*(.+)'),
    ]:
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            info[key] = match.group(1).strip()
    return {"raw": output, "info": info}

def run_dirb(target):
    cmd = "dirb http://" + target + " /usr/share/dirb/wordlists/common.txt -S -r"
    output = run_cmd(cmd, timeout=120)
    found = []
    for line in output.splitlines():
        if line.startswith("+ ") or "DIRECTORY:" in line:
            found.append(line.strip())
    return {"raw": output, "found": found[:30]}

def run_sslscan(target):
    cmd = "sslscan --no-colour " + target
    output = run_cmd(cmd, timeout=60)
    issues = []
    for line in output.splitlines():
        low = line.lower()
        if any(k in low for k in ["vulnerable","weak","sslv2","sslv3","tls 1.0","tls 1.1","expired","self-signed"]):
            issues.append(line.strip())
    return {"raw": output, "issues": issues}

def run_dnsrecon(target):
    cmd = "dnsrecon -d " + target + " -t std"
    output = run_cmd(cmd, timeout=60)
    records = []
    for line in output.splitlines():
        if re.search(r'\s(A|MX|NS|TXT|CNAME|SOA|PTR)\s', line):
            records.append(line.strip())
    return {"raw": output, "records": records[:20]}

def run_msf_scan(ip):
    rc = "use auxiliary/scanner/portscan/tcp\nset RHOSTS " + ip + "\nset PORTS 21,22,23,25,80,443,445,3306,3389,8080,8443\nset THREADS 10\nrun\nexit\n"
    with open("/tmp/msf_scan.rc", "w") as f:
        f.write(rc)
    output = run_cmd("msfconsole -q -r /tmp/msf_scan.rc", timeout=120)
    open_ports = []
    for line in output.splitlines():
        m = re.search(r':(\d+)\s+-\s+TCP OPEN', line)
        if m:
            open_ports.append(int(m.group(1)))
    return {"raw": output, "msf_open_ports": open_ports}

def run_curl_headers(target):
    cmd = "curl -s -I -L --max-time 15 http://" + target
    output = run_cmd(cmd, timeout=20)
    headers = {}
    missing_security = []
    security_headers = ["X-Frame-Options","X-Content-Type-Options","Content-Security-Policy","Strict-Transport-Security","X-XSS-Protection","Referrer-Policy"]
    for line in output.splitlines():
        if ": " in line:
            k, v = line.split(": ", 1)
            headers[k.strip()] = v.strip()
    for h in security_headers:
        if h.lower() not in [k.lower() for k in headers]:
            missing_security.append(h)
    return {"raw": output, "headers": headers, "missing_security": missing_security}

# ── scoring ───────────────────────────────────────────────────────────────────

CRITICAL_PORTS = {23, 445, 3389, 5900, 4444}
RISKY_PORTS    = {21, 22, 25, 110, 135, 137, 139, 1433, 3306, 8080, 8443}
RISKY_KEYWORDS = ["sql injection","xss","csrf","traversal","remote file","disclosure","credential","outdated","vulnerable","backdoor","misconfigured","buffer overflow","rce","arbitrary","bypass","injection","exploit"]

def calculate_score(nmap, nikto, ssl, headers, dirb, msf):
    score, reasons = 0.0, []
    all_ports = set(nmap.get("open_ports",[])) | set(msf.get("msf_open_ports",[]))

    crit = all_ports & CRITICAL_PORTS
    if crit:
        score += 2.0
        reasons.append(f"Critical ports open: {sorted(crit)}")

    risky = (all_ports & RISKY_PORTS) - CRITICAL_PORTS
    if risky:
        score += 1.0
        reasons.append(f"Risky ports open: {sorted(risky)}")

    if len(all_ports) > 10:
        score += 0.5
        reasons.append(f"Large attack surface: {len(all_ports)} open ports")

    findings = nikto.get("findings", [])
    crit_f = [f for f in findings if any(k in f.lower() for k in RISKY_KEYWORDS)]
    if crit_f:
        score += min(len(crit_f) * 0.4, 2.0)
        reasons.append(f"{len(crit_f)} critical web vulnerabilities")
    elif findings:
        score += 0.5
        reasons.append(f"{len(findings)} web findings detected")

    ssl_issues = ssl.get("issues", [])
    if ssl_issues:
        score += min(len(ssl_issues) * 0.3, 1.0)
        reasons.append(f"{len(ssl_issues)} SSL/TLS issue(s)")

    missing = headers.get("missing_security", [])
    if len(missing) >= 4:
        score += 0.5
        reasons.append(f"{len(missing)} missing security headers")

    dirb_found = dirb.get("found", [])
    if len(dirb_found) > 5:
        score += 0.5
        reasons.append(f"{len(dirb_found)} exposed directories found")

    score = round(min(score, 5.0), 1)
    if score == 0:     level, color = "SECURE",    "#00ff9d"
    elif score <= 1:   level, color = "LOW RISK",  "#a8ff78"
    elif score <= 2:   level, color = "MODERATE",  "#ffdd57"
    elif score <= 3.5: level, color = "HIGH RISK", "#ff9933"
    else:              level, color = "CRITICAL",  "#ff3c5a"

    return {"score": score, "level": level, "color": color, "reasons": reasons}

# ── routes ────────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    data   = request.get_json()
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "No target provided"}), 400

    ip        = resolve_ip(target)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    results   = {}

    def _nmap():    results['nmap']    = run_nmap(ip)
    def _nikto():   results['nikto']   = run_nikto(target)
    def _whatweb(): results['whatweb'] = run_whatweb(target)
    def _whois():   results['whois']   = run_whois(target)
    def _dirb():    results['dirb']    = run_dirb(target)
    def _ssl():     results['ssl']     = run_sslscan(target)
    def _dns():     results['dns']     = run_dnsrecon(target)
    def _msf():     results['msf']     = run_msf_scan(ip)
    def _headers(): results['headers'] = run_curl_headers(target)

    threads = [
        threading.Thread(target=fn) for fn in
        [_nmap, _nikto, _whatweb, _whois, _dirb, _ssl, _dns, _msf, _headers]
    ]
    for t in threads: t.start()
    for t in threads: t.join(timeout=200)

    scoring = calculate_score(
        results.get('nmap',    {}),
        results.get('nikto',   {}),
        results.get('ssl',     {}),
        results.get('headers', {}),
        results.get('dirb',    {}),
        results.get('msf',     {})
    )

    return jsonify({
        "target":    target,
        "ip":        ip,
        "timestamp": timestamp,
        "nmap":      results.get('nmap',    {"raw": "[NOT RUN]", "open_ports": [], "services": []}),
        "nikto":     results.get('nikto',   {"raw": "[NOT RUN]", "findings": []}),
        "whatweb":   results.get('whatweb', {"raw": "[NOT RUN]", "technologies": []}),
        "whois":     results.get('whois',   {"raw": "[NOT RUN]", "info": {}}),
        "dirb":      results.get('dirb',    {"raw": "[NOT RUN]", "found": []}),
        "ssl":       results.get('ssl',     {"raw": "[NOT RUN]", "issues": []}),
        "dns":       results.get('dns',     {"raw": "[NOT RUN]", "records": []}),
        "msf":       results.get('msf',     {"raw": "[NOT RUN]", "msf_open_ports": []}),
        "headers":   results.get('headers', {"raw": "[NOT RUN]", "headers": {}, "missing_security": []}),
        "score":     scoring,
    })

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
