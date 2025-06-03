import socket
import threading
import json
import time
from datetime import datetime
from flask import Flask, render_template, request, jsonify
import geoip2.database
import os

app = Flask(__name__)

# MaxMind GeoLite2-City.mmdb path
GEOIP_DB_PATH = "./GeoLite2-City.mmdb"

# Global scan log
scan_logs = []

def get_geo_info(ip):
    try:
        if not os.path.exists(GEOIP_DB_PATH):
            return {"country": "Unknown", "city": "Unknown"}
        with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
            response = reader.city(ip)
            return {
                "country": response.country.name or "Unknown",
                "city": response.city.name or "Unknown"
            }
    except Exception:
        return {"country": "Unknown", "city": "Unknown"}

def port_scan_worker(host, ports, results):
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                if s.connect_ex((host, port)) == 0:
                    results.append(port)
        except:
            pass

def split_port_range(start, end, threads=20):
    step = max((end - start + 1) // threads, 1)
    return [(i, min(i + step - 1, end)) for i in range(start, end + 1, step)]

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    host = data.get("host")
    port_range = data.get("range", "1-1024")
    user = data.get("name", "Anonymous")

    blocked_hosts = ["0.0.0.0", "127.0.0.1", "localhost"]
    if host.strip() in blocked_hosts:
        return jsonify({"error": f"Scanning '{host}' is not allowed."}), 400

    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return jsonify({"error": "Invalid host."}), 400

    start_port, end_port = map(int, port_range.split("-"))
    open_ports = []
    threads = []

    for start, end in split_port_range(start_port, end_port):
        thread = threading.Thread(target=port_scan_worker, args=(ip, range(start, end + 1), open_ports))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    threat_level = "Low" if len(open_ports) < 10 else "Medium" if len(open_ports) < 50 else "High"
    geo_info = get_geo_info(ip)

    timestamp = datetime.utcnow().isoformat()
    log_entry = {
        "host": host,
        "ip": ip,
        "ports": open_ports,
        "threat_level": threat_level,
        "geo": geo_info,
        "user": user,
        "time": timestamp
    }
    scan_logs.append(log_entry)

    return jsonify({
        "ip": ip,
        "open_ports": sorted(open_ports),
        "threat_level": threat_level,
        "geo": geo_info,
        "scan_time": timestamp
    })

@app.route("/logs")
def logs():
    return jsonify(scan_logs)

@app.route("/download_logs")
def download_logs():
    response = app.response_class(
        response=json.dumps(scan_logs, indent=2),
        mimetype='application/json'
    )
    response.headers.set("Content-Disposition", "attachment", filename="psx_scan_logs.json")
    return response

if __name__ == "__main__":
    app.run(debug=True)
