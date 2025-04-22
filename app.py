import hashlib
import socket
import psutil
import os
import yara
import subprocess
import json
import requests
from datetime import datetime
from flask import Flask, jsonify, render_template, request, send_file, Response
from collections import Counter
import csv
from io import StringIO
import pdfkit

path_wkhtmltopdf = r"C:\Users\hp\Downloads\wkhtmltox-0.12.6-1.mxe-cross-win64\wkhtmltox\bin\wkhtmltopdf.exe"
config = pdfkit.configuration(wkhtmltopdf=path_wkhtmltopdf)

app = Flask(__name__)

SUSPICIOUS_PATHS = ['AppData', 'Temp', 'Roaming']
YARA_RULES_FILE = 'rules.yar'

yara_rules = None
try:
    if os.path.exists(YARA_RULES_FILE):
        yara_rules = yara.compile(filepaths={YARA_RULES_FILE: YARA_RULES_FILE})
    else:
        print(f"YARA rule file not found: {YARA_RULES_FILE}")
except Exception as e:
    print(f"YARA rule loading failed: {e}")

def is_suspicious_path(path):
    return any(s in path for s in SUSPICIOUS_PATHS)

def calculate_file_hash(filepath):
    try:
        with open(filepath, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None

def scan_file_with_yara(filepath):
    matches_data = []
    try:
        if yara_rules and os.path.isfile(filepath):
            matches = yara_rules.match(filepath)
            for match in matches:
                strings_matched = [value for _, _, value in match.strings]
                matches_data.append({
                    'rule': match.rule,
                    'strings': strings_matched
                })
        return matches_data
    except Exception:
        return []

def extract_urls_from_cmdline(cmdline):
    if not cmdline:
        return []
    urls = []
    for arg in cmdline:
        if arg.startswith("http://") or arg.startswith("https://"):
            urls.append(arg)
    return urls

def check_signature_status(path):
    if not path or not os.path.isfile(path):
        return "Unknown"
    try:
        result = subprocess.run(['sigcheck64.exe', '-q', '-n', '-c', path], capture_output=True, text=True)
        return "Signed" if "Signed" in result.stdout else "Unsigned"
    except Exception:
        return "Unknown"

def get_geoip(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        if response.status_code == 200:
            return response.json().get('country', 'Unknown')
    except Exception:
        pass
    return "Unknown"

def get_process_info():
    process_list = []
    top_cpu = []
    parent_pid_counts = Counter()
    signature_stats = {"Signed": 0, "Unsigned": 0, "Unknown": 0}
    geoip_countries = Counter()

    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status', 'exe', 'ppid', 'cmdline']):
        try:
            info = proc.info
            path = info.get('exe') or ''
            suspicious_flags = []
            risk_score = 0  

            if is_suspicious_path(path):
                suspicious_flags.append('Unusual Execution Path')
                risk_score += 3  
            if info['cpu_percent'] > 70:
                suspicious_flags.append('High CPU Usage')
                risk_score += 2 
            if info['memory_percent'] > 70:
                suspicious_flags.append('High Memory Usage')
                risk_score += 2  
            file_hash = calculate_file_hash(path)

            parent_name = ''
            try:
                parent = psutil.Process(info['ppid'])
                parent_name = parent.name()
                if parent_name.lower() in ['winword.exe', 'excel.exe', 'powershell.exe']:
                    suspicious_flags.append(f'Suspicious Parent: {parent_name}')
                    risk_score += 1  
            except Exception:
                parent_name = 'Unknown'

            connections = []
            external_ips = []
            try:
                for conn in proc.net_connections(kind='inet'):
                    if conn.raddr:
                        ip_port = f"{conn.raddr.ip}:{conn.raddr.port}"
                        connections.append(ip_port)
                        suspicious_flags.append("External Network Activity")
                        geoip_countries[get_geoip(conn.raddr.ip)] += 1
                        external_ips.append(conn.raddr.ip)
            except Exception:
                pass

            yara_matches = scan_file_with_yara(path)
            if yara_matches:
                for match in yara_matches:
                    suspicious_flags.append(f"YARA Match: {match['rule']}")
                    risk_score += 3  

            urls_opened = extract_urls_from_cmdline(info.get('cmdline'))
            if urls_opened:
                suspicious_flags.append("Opened URL(s) from CLI")
                risk_score += 1  

            signature = check_signature_status(path)
            signature_stats[signature] += 1

            parent_pid_counts[info['ppid']] += 1

            process_list.append({
                'name': info['name'],
                'pid': info['pid'],
                'ppid': info['ppid'],
                'parent_name': parent_name,
                'cpu': info['cpu_percent'],
                'memory': info['memory_percent'],
                'status': info['status'],
                'path': path,
                'hash': file_hash,
                'network_connections': connections,
                'suspicious': suspicious_flags,
                'urls': urls_opened,
                'yara_matches': yara_matches,
                'timestamp': datetime.now().isoformat(),
                'signature': signature,
                'geoip': external_ips,
                'risk_score': risk_score 
            })

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    top_cpu = sorted(process_list, key=lambda x: x['cpu'], reverse=True)[:5]
    return {
        'processes': process_list,
        'top_cpu': top_cpu,
        'parent_pids': dict(parent_pid_counts),
        'signature_status': signature_stats,
        'geoip_countries': dict(geoip_countries)
    }

@app.route('/kill_process/<int:pid>', methods=['POST'])
def kill_process(pid):
    try:
        proc = psutil.Process(pid)
        proc.terminate()  # Or use proc.kill() for forceful termination
        return jsonify({"status": "success", "message": f"Process {pid} terminated."}), 200
    except psutil.NoSuchProcess:
        return jsonify({"status": "error", "message": "Process not found."}), 404

@app.route('/export_csv', methods=['GET'])
def export_csv():
    process_data = get_process_info()['processes']
    si = StringIO()
    writer = csv.DictWriter(si, fieldnames=process_data[0].keys())
    writer.writeheader()
    writer.writerows(process_data)
    si.seek(0)
    return send_file(si, mimetype='text/csv', as_attachment=True, download_name='process_data.csv')

@app.route('/export_pdf', methods=['GET'])
def export_pdf():
    process_data = get_process_info()['processes']
    
  
    html = render_template('pdf_template.html', processes=process_data)
   
    try:
        pdf = pdfkit.from_string(html, False, configuration=config)
        return Response(pdf, mimetype='application/pdf',
                        headers={'Content-Disposition': 'attachment; filename=process_report.pdf'})
    except Exception as e:
        return jsonify({"status": "error", "message": f"PDF generation failed: {str(e)}"}), 500

@app.route('/snapshot', methods=['GET'])
def snapshot():
    
    snapshot_data = get_process_info()
    
    return jsonify({"status": "success", "message": "Snapshot taken successfully."})

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/processes')
def processes():
    return jsonify(get_process_info())

if __name__ == '__main__':
    app.run(debug=True, port=8080)
