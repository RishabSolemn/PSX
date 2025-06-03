from flask import Flask, request, render_template, jsonify, send_file
import socket
import threading
import json
import os
import requests
import time
from datetime import datetime

app = Flask(__name__)
LOG_FILE = 'logs/scan_log.json'

# Known ports for AI-like interpretation
PORT_KNOWLEDGE = {
    21: "FTP - File Transfer Protocol",
    22: "SSH - Secure Shell",
    23: "Telnet - Unsecure Remote Access",
    25: "SMTP - Email Sending",
    53: "DNS - Domain Name System",
    80: "HTTP - Web Traffic",
    110: "POP3 - Email Retrieval",
    143: "IMAP - Email Retrieval",
    443: "HTTPS - Secure Web Traffic",
    3306: "MySQL Database",
    3389: "RDP - Remote Desktop",
    8080: "HTTP Alternate",
}

# Scan a single port
def scan_port(host, port, open_ports):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex((host, port)) == 0:
                description = PORT_KNOWLEDGE.get(port, "Unknown Service")
                open_ports.append({"port": port, "description": description})
    except:
        pass

# Real IP resolver
def resolve_real_ip(host):
    try:
        return socket.gethostbyname(host)
    except:
        return None

# Deception checker
def detect_deception(domain):
    try:
        ip = socket.gethostbyname(domain)
        # Check for common CDN masks (Cloudflare, Akamai, etc.)
        suspicious_ranges = ["104.", "172.", "198.", "23.", "34.", "35."]
        return any(ip.startswith(prefix) for prefix in suspicious_ranges)
    except:
        return False

# GeoIP Lookup (free fallback)
def get_geo_data(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}").json()
        return {
            "city": response.get("city", "Unknown"),
            "country": response.get("country", "Unknown"),
            "lat": response.get("lat", 0),
            "lon": response.get("lon", 0),
        }
    except:
        return {"city": "Unknown", "country": "Unknown", "lat": 0, "lon": 0}

# Save logs
def save_log(entry):
    os.makedirs('logs', exist_ok=True)
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r') as f:
            try:
                logs = json.load(f)
            except:
                logs = []

    logs.append(entry)
    with open(LOG_FILE, 'w') as f:
        json.dump(logs, f, indent=2)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    host = data.get('host')
    name = data.get('name', 'Anonymous')
    port_range = data.get('range', '1-1024')

    if not host:
        return jsonify({"error": "Missing host"}), 400

    try:
        start_port, end_port = map(int, port_range.split('-'))
    except:
        return jsonify({"error": "Invalid port range"}), 400

    open_ports = []
    threads = []

    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan_port, args=(host, port, open_ports))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    real_ip = resolve_real_ip(host)
    deception = detect_deception(host)
    geo = get_geo_data(real_ip)

    result = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scanned_by": name,
        "target": host,
        "real_ip": real_ip,
        "open_ports": sorted(open_ports, key=lambda x: x["port"]),
        "geo": geo,
        "deception": deception,
    }

    save_log(result)
    return jsonify(result)

@app.route('/download-log')
def download_log():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w') as f:
            f.write("[]")
    return send_file(LOG_FILE, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)

