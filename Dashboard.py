from flask import Flask, render_template, request, jsonify, redirect, url_for, session, make_response
import requests
import base64
import csv
import io
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = "watchguard_secure_key_123" 

# --- CONFIGURATION ---
ACCOUNT_ID = "ACC-3702426"
BASE_URL = "https://api.jpn.cloud.watchguard.com" 
WG_API_KEY = "bTgcZlm6v8nQhnbh86Vo2Ai80jP4MJbg7nfwWb4F"

# --- DARKTRACE CONFIG ---
DT_BASE_URL = "https://your-darktrace-appliance-url"
DT_TOKEN = "your-darktrace-api-token"

# Cache สำหรับกันยิง Darktrace ซ้ำ (เก็บใน Memory)
# { "device_id": datetime_object }
sent_alerts_cache = {}

# --- HELPER FUNCTIONS ---

def get_token(acc_id, api_key):
    try:
        auth_string = f"{acc_id}:{api_key}"
        encoded_auth = base64.b64encode(auth_string.encode()).decode()
        headers = {
            'Authorization': f'Basic {encoded_auth}', 
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        res = requests.post(f"{BASE_URL}/oauth/token", headers=headers, data={'grant_type': 'client_credentials'}, timeout=10)
        return res.json().get('access_token') if res.status_code == 200 else None
    except Exception as e:
        print(f"Token Error: {e}")
        return None

def push_alert_to_darktrace(device_name, ip_address, malware_count, device_id, last_conn): # เพิ่ม last_conn
    last_sent = sent_alerts_cache.get(device_id)
    if last_sent and (datetime.now() - last_sent) < timedelta(hours=1):
        return False

    dt_url = f"{DT_BASE_URL}/api/ingest/alert"
    payload = {
        "alert_type": "WatchGuard Malware Detection",
        "device_name": device_name,
        "source_ip": ip_address,
        "last_connection": last_connection,
        "description": f"WatchGuard detected {malware_count} malware(s)",
        "severity": 3 if malware_count > 1 else 2,
        "timestamp": datetime.utcnow().isoformat()
    }
    headers = {"DT-Token": DT_TOKEN, "Content-Type": "application/json"}
    try:
        res = requests.post(dt_url, json=payload, headers=headers, timeout=5, verify=False)
        if res.status_code == 200:
            sent_alerts_cache[device_id] = datetime.now() # บันทึกลง Cache
            return True
        return False
    except:
        return False

# --- ROUTES ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        acc_id = request.form.get('access_id')
        key = request.form.get('api_key')
        token = get_token(acc_id, key)
        if token:
            session['access_id'] = acc_id
            session['api_key'] = key
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error="Credentials ไม่ถูกต้อง")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Dashboard.py (ฉบับปรับปรุง)
@app.route('/')
def index():
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    token = get_token(session.get('access_id'), session.get('api_key'))
    if not token:
        return redirect(url_for('logout'))

    days = int(request.args.get('days', 7))
    start_date = (datetime.utcnow() - timedelta(days=days)).strftime('%Y-%m-%d')
    headers = {'Authorization': f'Bearer {token}', 'WatchGuard-API-Key': WG_API_KEY}


    # 1. กำหนด Filter สำหรับดึงข้อมูลย้อนหลัง 3 เดือน (last 3 months)
    # filter=32001 AmongTheLast [3,2] คือ Unit=Months (2), Value=3
    event_filter = "33001%AmongTheLast%[1,1]"

    try:
        # Fetch Data หลักๆ เท่านั้น
        dev_res = requests.get(f"{BASE_URL}/rest/endpoint-security/management/api/v1/accounts/{ACCOUNT_ID}/devices", headers=headers, timeout=15)
        det_res = requests.get(f"{BASE_URL}/rest/endpoint-security/management/api/v1/accounts/{ACCOUNT_ID}/detections?date_from={start_date}", headers=headers, timeout=15)
       # 2. เรียก API เพื่อดึง Security Event Counters
        # ใช้หัวข้อ 255 เพื่อดึง Counters ทั้งหมด
        counter_url = f"{BASE_URL}/rest/endpoint-security/management/api/v1/accounts/{ACCOUNT_ID}/securityeventcounters/255?filter={event_filter}"
        counter_res = requests.get(counter_url, headers=headers, timeout=15)
        event_data = counter_res.json().get('data', {})
        event_counts = event_data.get('counts', [])
        # เตรียมสรุปข้อมูลสำหรับแสดงใน Panel
        # เช่น ดึงค่า Malware (1), PUP (2), Exploit (3) เป็นต้น
        security_events = {
            "malware": next((item['count'] for item in event_counts if item['type'] == 1), 0),
            "pup": next((item['count'] for item in event_counts if item['type'] == 2), 0),
            "exploit": next((item['count'] for item in event_counts if item['type'] == 3), 0),
            "total": sum(item['count'] for item in event_counts)
        }

        raw_devices = dev_res.json().get('data', [])
        raw_detections = det_res.json().get('data', [])
            
        threat_map = {}
        for det in raw_detections:
            d_id = det.get('device_id')
            m_count[d_id] = threat_map.get(d_id, 0) + 1

        processed_devices = []
        stats = {"total": 0, "threats": 0, "isolated": 0}

        for d in raw_devices:
            d_id = d.get('device_id')
            m_count = threat_map.get(d_id, 0)
            status_val = str(d.get('isolation_state', 0))
            
            dev_data = {
                "id": d_id,
                "name": d.get('host_name', 'Unknown').replace("'", "\\'"),
                "ip": d.get('ip_address', '-'),
                "status": status_val,
                "malware_count": m_count,
                "last_conn": d.get('last_connection', '-'),
                # --- เพิ่มข้อมูลใหม่ตรงนี้ ---
                "os": d.get('operating_system', 'N/A'),
                "agent_version": d.get('agent_version', 'N/A'),
                "domain": d.get('domain', 'N/A'),
                "group": d.get('custom_group_folder_path', 'Default Group')
            }
            processed_devices.append(dev_data)
            
            stats["total"] += 1
            if m_count > 0: stats["threats"] += 1
            if status_val == "1": stats["isolated"] += 1

            security_stats = [
            {"label": "Total Assets", "count": stats["total"]},
            {"label": "Isolated", "count": stats["isolated"]},
            {"label": "Active Threats", "count": stats["threats"]},
            {"label": "Secure Devices", "count": stats["total"] - stats["threats"]}
]

        return render_template('index.html', 
                       devices=processed_devices, 
                       current_days=days, 
                       stats=stats,
                       security_events=security_events) # ส่งตัวแปรนี้ไปด้วย
        #return render_template('index.html', devices=processed_devices, current_days=days, stats=stats)
    except Exception as e:
        return f"❌ Data Fetch Error: {str(e)}"
@app.route('/export')
def export_data():
    if 'logged_in' not in session: return redirect(url_for('login'))
    
    # ดึงข้อมูลล่าสุดเพื่อทำ CSV (Logic ย่อจาก index)
    token = get_token(session.get('access_id'), session.get('api_key'))
    headers = {'Authorization': f'Bearer {token}', 'WatchGuard-API-Key': WG_API_KEY}
    dev_res = requests.get(f"{BASE_URL}/rest/endpoint-security/management/api/v1/accounts/{ACCOUNT_ID}/devices", headers=headers)
    devices = dev_res.json().get('data', [])

    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['Hostname', 'IP Address', 'Isolation Status', 'Last Connection'])
    
    for d in devices:
        status = "Isolated" if d.get('isolation_state') == 1 else "Normal"
        cw.writerow([d.get('host_name'), d.get('ip_address'), status, d.get('last_connection_date')])

    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = f"attachment; filename=watchguard_report_{datetime.now().strftime('%Y%m%d')}.csv"
    output.headers["Content-type"] = "text/csv"
    return output

@app.route('/action', methods=['POST'])
def action():
    if 'logged_in' not in session: return jsonify({"status": "error"}), 401
    token = get_token(session.get('access_id'), session.get('api_key'))
    data = request.json
    url = f"{BASE_URL}/rest/endpoint-security/management/api/v1/accounts/{ACCOUNT_ID}/devices/{data.get('action')}"
    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json', 'WatchGuard-API-Key': WG_API_KEY}
    payload = {"device_ids": [data.get('id')]}
    if data.get('action') == "isolation":
        payload.update({"customized_message": "Isolated by Admin", "hide_customized_alert": False})
    
    try:
        res = requests.post(url, headers=headers, json=payload, timeout=15)
        return jsonify({"status": "success"}) if res.status_code in [200, 201, 202, 204] else jsonify({"status": "error"})
    except:
        return jsonify({"status": "error"})



if __name__ == '__main__':
 app.run(host='0.0.0.0', debug=True, port=5000)
   
  
    