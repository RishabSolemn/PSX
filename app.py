from flask import Flask, render_template, request, jsonify
import socket
import json
import threading
import time

app = Flask(__name__)

def scan_port(host, port, results):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((host, port))
            if result == 0:
                results.append(port)
    except:
        pass

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    host = data.get('host')
    port_range = data.get('range', '1-1024')
    name = data.get('name', 'Anonymous')

    try:
        start_port, end_port = map(int, port_range.split('-'))
    except:
        return jsonify({'error': 'Invalid port range format.'})

    open_ports = []
    threads = []

    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan_port, args=(host, port, open_ports))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    threat_level = 'Low'
    if len(open_ports) > 50:
        threat_level = 'High'
    elif len(open_ports) > 20:
        threat_level = 'Medium'

    return jsonify({
        'ip': host,
        'geo': {'city': 'Unknown', 'country': 'Unknown'},
        'threat_level': threat_level,
        'open_ports': open_ports
    })
