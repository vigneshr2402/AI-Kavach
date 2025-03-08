from flask import Flask, render_template, jsonify, request, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from flask_cors import CORS
import os
import datetime
import logging
import threading
import sys
import re
from collections import Counter
import validators  # Ensure this package is installed: pip install validators

# Ensure 'detection' directory is in the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import email alert function
from detection.email_alerts import send_email_alert  

# Initialize Flask App
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__, template_folder="../dashboard/templates", static_folder="../dashboard/static")

# Setup Database Path
DATA_DIR = os.path.join(BASE_DIR, "database")
DB_PATH = os.path.join(DATA_DIR, "threats.db")
os.makedirs(DATA_DIR, exist_ok=True)

app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize Extensions
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")
CORS(app)

# Configure Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Threat Model with Categorization
class Threat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)
    src_ip = db.Column(db.String, nullable=False)
    dst_ip = db.Column(db.String, nullable=False)
    packet_size = db.Column(db.Integer, nullable=False)
    category = db.Column(db.String, nullable=False, default="Unknown")

# 🛑 **Step 1: Create Suspicious URL Model**
class SuspiciousURL(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)
    url = db.Column(db.String, nullable=False)
    flagged_reason = db.Column(db.String, nullable=False)

# Ensure Database is Initialized
with app.app_context():
    db.create_all()

@app.route("/")
def index():
    threats = Threat.query.order_by(Threat.id.desc()).limit(10).all()
    return render_template("dashboard.html", threats=threats)

@app.route("/logs")
def fetch_logs():
    threats = Threat.query.order_by(Threat.id.desc()).limit(10).all()
    logs = [{
        "timestamp": t.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "category": t.category,
        "message": f"{t.category} Attack: {t.src_ip} → {t.dst_ip} | Size: {t.packet_size}"
    } for t in threats]
    return jsonify({"logs": logs})

@app.route("/blocked_ips")
def get_blocked_ips():
    attacker_ips = [
        ip[0] for ip in Threat.query.with_entities(Threat.src_ip)
        .filter(Threat.category.in_(["DDoS", "SQL Injection"]))
        .distinct().all()
    ]
    return jsonify({"blocked_ips": attacker_ips})

@app.route("/favicon.ico")
def favicon():
    return send_from_directory(app.static_folder, "favicon.ico", mimetype="image/vnd.microsoft.icon")

@app.route("/get_threats")
@app.route("/api/threats")
def get_threats():
    threats = Threat.query.order_by(Threat.id.desc()).limit(100).all()
    return jsonify([{
        "id": t.id,
        "timestamp": t.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": t.src_ip,
        "dst_ip": t.dst_ip,
        "packet_size": t.packet_size,
        "category": t.category
    } for t in threats])

# 🛑 **Step 2: Update URL Checking API**
SUSPICIOUS_KEYWORDS = ["phishing", "malware", "hacked", "exploit", "darkweb"]

@app.route("/check_url", methods=["GET"])
def check_url():
    url = request.args.get("url")
    
    if not url or not validators.url(url):
        return jsonify({"error": "Invalid URL"}), 400
    
    is_suspicious = any(keyword in url.lower() for keyword in SUSPICIOUS_KEYWORDS)

    if is_suspicious:
        flagged_reason = "Matched suspicious keywords"
        # Store in database
        new_entry = SuspiciousURL(url=url, flagged_reason=flagged_reason)
        db.session.add(new_entry)
        db.session.commit()
        send_email_alert("Suspicious Link Detected", url, 0)  

    return jsonify({"url": url, "suspicious": is_suspicious})

# 📊 **Step 3: Add API to Fetch Suspicious URLs**
@app.route("/api/suspicious_urls")
def get_suspicious_urls():
    urls = SuspiciousURL.query.order_by(SuspiciousURL.id.desc()).limit(20).all()
    return jsonify([{
        "timestamp": url.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "url": url.url,
        "flagged_reason": url.flagged_reason
    } for url in urls])

# 📊 API: Get Threats Over Time
@app.route("/api/threats_over_time")
def threats_over_time():
    threats = Threat.query.with_entities(Threat.timestamp).all()
    threats_count = Counter(t.timestamp.strftime("%Y-%m-%d %H:00") for t in threats)
    threats_data = [{"time": key, "count": threats_count[key]} for key in sorted(threats_count.keys())]
    return jsonify(threats_data)

# 🔥 API: Get Top Attack Sources
@app.route("/api/top_attack_sources")
def top_attack_sources():
    threats = Threat.query.with_entities(Threat.src_ip).all()
    ip_count = Counter(t.src_ip for t in threats)
    top_ips = [{"ip": ip, "count": count} for ip, count in ip_count.most_common(5)]
    return jsonify(top_ips)

def classify_threat(packet_size, src_ip, dst_ip):
    if packet_size > 1000:
        return "DDoS"
    elif src_ip.startswith("192.168"):
        return "Internal Scan"
    elif "sql" in dst_ip.lower():
        return "SQL Injection"
    else:
        return "Suspicious Activity"

def broadcast_logs():
    with app.app_context():
        try:
            threats = Threat.query.order_by(Threat.id.desc()).limit(10).all()
            logs = [{
                "timestamp": t.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "category": t.category,
                "message": f"{t.category} Attack: {t.src_ip} → {t.dst_ip} | Size: {t.packet_size}"
            } for t in threats]
            socketio.emit("log_update", {"logs": logs})
        except Exception as e:
            logging.error(f"Failed to broadcast logs: {e}")

@app.route("/simulate_threat")
def simulate_threat():
    try:
        category = classify_threat(750, "192.168.1.15", "1.1.1.1")
        new_threat = Threat(
            src_ip="192.168.1.15", 
            dst_ip="1.1.1.1", 
            packet_size=750,
            category=category
        )
        db.session.add(new_threat)
        db.session.commit()

        if category in ["DDoS", "SQL Injection"]:
            send_email_alert(new_threat.src_ip, new_threat.dst_ip, new_threat.packet_size)
        
        socketio.emit('new_threat', {
            "id": new_threat.id,
            "timestamp": new_threat.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": new_threat.src_ip,
            "dst_ip": new_threat.dst_ip,
            "packet_size": new_threat.packet_size,
            "category": new_threat.category
        })
        
        threading.Thread(target=broadcast_logs, daemon=True).start()
        return jsonify({"message": "Threat added!", "category": category}), 200
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error in simulate_threat: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    logging.info("Starting AI-Kavach Dashboard...")
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)

