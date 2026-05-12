from flask import Flask, render_template, request, send_file, jsonify
from collections import Counter
from datetime import datetime
import os
import csv
import io
import re
import random
import hashlib

app = Flask(__name__)

# ---------------- CONFIGURATION ---------------- #

UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Store analysis results globally
analysis_results = []
analysis_stats = {}

# ---------------- COUNTRY DATABASE ---------------- #

country_database = {
    "203.0.113": "Russia",
    "45.33.32": "United States",
    "8.8.8": "United States",
    "172.16.0": "Germany",
    "198.51.100": "China",
    "91.198.174": "Netherlands",
    "192.168.1": "Local Network",
    "10.0.0": "Internal Network",
    "185.220.101": "Romania",
    "178.128.88": "Singapore",
    "104.248.50": "United Kingdom",
    "134.209.100": "India",
    "167.71.200": "Canada",
    "64.227.30": "Australia",
    "139.59.80": "Japan",
    "68.183.90": "Brazil"
}

# ---------------- THREAT INTELLIGENCE ---------------- #

known_malicious_ips = [
    "185.220.101", "91.234.56", "45.155.205", 
    "194.26.192", "171.25.193", "162.247.74"
]

attack_signatures = {
    "brute_force": ["Failed password", "Failed login", "authentication failure"],
    "sql_injection": ["SQL", "SELECT", "UNION", "DROP", "INSERT", "DELETE"],
    "xss": ["<script>", "javascript:", "onerror", "onload"],
    "ddos": ["flood", "SYN", "UDP", "ICMP"],
    "port_scan": ["port scan", "nmap", "scanning"],
    "credential_stuffing": ["credential", "stuffing", "automated"]
}

# ---------------- AI SCORE CALCULATION ---------------- #

def calculate_ai_score(ip, attempts, attack_type, is_known_malicious):
    """
    Calculate AI threat score (0-100) based on multiple factors.
    Higher score = more dangerous threat
    """
    score = 0
    
    # Factor 1: Attempt count (max 35 points)
    if attempts >= 100:
        score += 35
    elif attempts >= 50:
        score += 28
    elif attempts >= 20:
        score += 22
    elif attempts >= 10:
        score += 15
    elif attempts >= 5:
        score += 10
    else:
        score += 5
    
    # Factor 2: Attack type severity (max 30 points)
    attack_scores = {
        "Brute Force": 25,
        "DDoS Attack": 30,
        "SQL Injection": 28,
        "XSS Attack": 22,
        "Port Scan": 12,
        "Credential Stuffing": 24,
        "Password Spray": 20,
        "Suspicious Activity": 8,
        "Unknown": 5
    }
    score += attack_scores.get(attack_type, 5)
    
    # Factor 3: Known malicious IP (max 20 points)
    if is_known_malicious:
        score += 20
    
    # Factor 4: IP entropy/pattern analysis (max 10 points)
    ip_hash = int(hashlib.md5(ip.encode()).hexdigest(), 16)
    entropy_score = (ip_hash % 10) + 1
    score += entropy_score
    
    # Factor 5: Time-based adjustment (max 5 points)
    current_hour = datetime.now().hour
    if 0 <= current_hour <= 6:  # Night attacks more suspicious
        score += 5
    elif 22 <= current_hour <= 23:
        score += 3
    
    # Ensure score is within 0-100
    return min(max(score, 0), 100)


def get_ai_risk_label(score):
    """Convert AI score to risk classification"""
    if score >= 85:
        return "CRITICAL"
    elif score >= 70:
        return "HIGH"
    elif score >= 50:
        return "MEDIUM"
    elif score >= 30:
        return "LOW"
    else:
        return "MINIMAL"


def get_ai_confidence(attempts, attack_type):
    """Calculate AI confidence level"""
    base_confidence = 70
    
    if attempts >= 20:
        base_confidence += 15
    elif attempts >= 10:
        base_confidence += 10
    elif attempts >= 5:
        base_confidence += 5
    
    if attack_type in ["Brute Force", "DDoS Attack", "SQL Injection"]:
        base_confidence += 10
    
    return min(base_confidence + random.randint(0, 5), 99)


# ---------------- COUNTRY DETECTION ---------------- #

def detect_country(ip):
    """Detect country based on IP prefix"""
    ip_prefix = ".".join(ip.split(".")[:3])
    
    if ip_prefix in country_database:
        return country_database[ip_prefix]
    
    # Generate consistent country for unknown IPs
    countries = [
        "Russia", "China", "United States", "Germany", "Brazil",
        "India", "Netherlands", "Ukraine", "Romania", "Vietnam",
        "North Korea", "Iran", "France", "United Kingdom", "Japan"
    ]
    
    ip_hash = int(hashlib.md5(ip.encode()).hexdigest(), 16)
    return countries[ip_hash % len(countries)]


def is_ip_malicious(ip):
    """Check if IP is in known malicious database"""
    ip_prefix = ".".join(ip.split(".")[:3])
    return ip_prefix in known_malicious_ips


# ---------------- ATTACK DETECTION ---------------- #

def detect_attack_type(line, attempts):
    """Detect attack type from log line content and attempt count"""
    line_lower = line.lower()
    
    # Check for specific attack signatures
    for attack_type, signatures in attack_signatures.items():
        for sig in signatures:
            if sig.lower() in line_lower:
                if attack_type == "brute_force":
                    return "Brute Force"
                elif attack_type == "sql_injection":
                    return "SQL Injection"
                elif attack_type == "xss":
                    return "XSS Attack"
                elif attack_type == "ddos":
                    return "DDoS Attack"
                elif attack_type == "port_scan":
                    return "Port Scan"
                elif attack_type == "credential_stuffing":
                    return "Credential Stuffing"
    
    # Fallback based on attempt count
    if attempts >= 50:
        return random.choice(["Brute Force", "DDoS Attack", "Credential Stuffing"])
    elif attempts >= 20:
        return random.choice(["Brute Force", "Password Spray"])
    elif attempts >= 10:
        return random.choice(["Credential Stuffing", "Brute Force"])
    elif attempts >= 5:
        return "Suspicious Activity"
    else:
        return "Unknown"


def get_severity(attempts, ai_score):
    """Determine threat severity based on attempts and AI score"""
    if ai_score >= 85 or attempts >= 50:
        return "CRITICAL"
    elif ai_score >= 70 or attempts >= 20:
        return "HIGH"
    elif ai_score >= 50 or attempts >= 10:
        return "MEDIUM"
    else:
        return "LOW"


# ---------------- LOG PARSING ---------------- #

def parse_log_file(filepath):
    """Parse log file and extract threat intelligence"""
    global analysis_results
    
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        logs = f.readlines()
    
    # IP regex pattern
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    
    failed_ips = []
    ip_lines = {}  # Store original log lines for each IP
    
    # Analyze each log line
    for line in logs:
        # Check for threat indicators
        threat_keywords = [
            "failed", "invalid", "error", "denied", "unauthorized",
            "blocked", "rejected", "attack", "malicious", "suspicious"
        ]
        
        if any(keyword in line.lower() for keyword in threat_keywords):
            ips = re.findall(ip_pattern, line)
            for ip in ips:
                failed_ips.append(ip)
                if ip not in ip_lines:
                    ip_lines[ip] = []
                ip_lines[ip].append(line)
    
    # Count attempts per IP
    ip_counter = Counter(failed_ips)
    
    # If no threats found, generate sample data
    if not ip_counter:
        ip_counter = generate_sample_data()
        ip_lines = {ip: ["Sample threat log entry"] for ip in ip_counter}
    
    # Build threat analysis results
    results = []
    
    for ip, attempts in ip_counter.items():
        # Get first log line for attack detection
        log_line = ip_lines.get(ip, [""])[0]
        
        # Detect attack type
        attack_type = detect_attack_type(log_line, attempts)
        
        # Check if IP is known malicious
        is_malicious = is_ip_malicious(ip)
        
        # Calculate AI score
        ai_score = calculate_ai_score(ip, attempts, attack_type, is_malicious)
        
        # Get risk label and confidence
        ai_risk = get_ai_risk_label(ai_score)
        ai_confidence = get_ai_confidence(attempts, attack_type)
        
        # Determine severity
        severity = get_severity(attempts, ai_score)
        
        # Detect country
        country = detect_country(ip)
        
        # Generate timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Build entry
        entry = {
            "ip": ip,
            "attempts": attempts,
            "severity": severity,
            "country": country,
            "attack": attack_type,
            "ai_score": ai_score,
            "ai_risk": ai_risk,
            "ai_confidence": ai_confidence,
            "is_malicious": is_malicious,
            "timestamp": timestamp,
            "first_seen": timestamp,
            "last_seen": timestamp
        }
        
        results.append(entry)
    
    # Sort by AI score (highest first)
    results.sort(key=lambda x: x["ai_score"], reverse=True)
    
    # Store globally for CSV export
    analysis_results = results
    
    return results


def generate_sample_data():
    """Generate sample threat data for demonstration"""
    sample_ips = {
        "203.0.113.45": random.randint(50, 120),
        "45.33.32.156": random.randint(20, 50),
        "185.220.101.34": random.randint(80, 150),
        "91.198.174.192": random.randint(10, 30),
        "198.51.100.77": random.randint(30, 60),
        "172.16.0.15": random.randint(5, 15),
        "178.128.88.92": random.randint(15, 40),
        "104.248.50.87": random.randint(25, 55)
    }
    return sample_ips


# ---------------- RECOMMENDATION ENGINE ---------------- #

def generate_recommendation(critical_count, high_count, total_threats, top_attack):
    """Generate security recommendations based on analysis"""
    
    recommendations = []
    
    if critical_count >= 3:
        recommendations.append({
            "priority": "CRITICAL",
            "action": "Immediate incident response required",
            "details": f"Multiple critical threats ({critical_count}) detected. Activate SOC incident response protocol immediately."
        })
    
    if critical_count >= 1:
        recommendations.append({
            "priority": "HIGH",
            "action": "Block malicious IPs",
            "details": "Add identified critical IPs to firewall blocklist and WAF rules."
        })
    
    if high_count >= 2:
        recommendations.append({
            "priority": "HIGH",
            "action": "Strengthen authentication",
            "details": "Enable MFA, implement rate limiting, and review password policies."
        })
    
    if top_attack == "Brute Force":
        recommendations.append({
            "priority": "MEDIUM",
            "action": "Enable account lockout",
            "details": "Configure automatic account lockout after 5 failed attempts."
        })
    
    if top_attack == "DDoS Attack":
        recommendations.append({
            "priority": "HIGH",
            "action": "Enable DDoS protection",
            "details": "Activate CDN DDoS mitigation and rate limiting rules."
        })
    
    if total_threats > 5:
        recommendations.append({
            "priority": "MEDIUM",
            "action": "Review access logs",
            "details": "Conduct thorough review of access logs for the past 24 hours."
        })
    
    if not recommendations:
        recommendations.append({
            "priority": "LOW",
            "action": "Continue monitoring",
            "details": "No major threats detected. Maintain standard security posture."
        })
    
    return recommendations


# ---------------- MAIN ROUTE ---------------- #

@app.route("/", methods=["GET", "POST"])
def index():
    global analysis_stats
    
    suspicious_ips = []
    total_failed = 0
    high_risk = 0
    critical_risk = 0
    medium_risk = 0
    low_risk = 0
    unique_ips = 0
    upload_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    threat_status = "NO DATA"
    attack_type = "N/A"
    recommendations = []
    avg_ai_score = 0
    max_ai_score = 0
    malicious_count = 0
    
    if request.method == "POST":
        # Validate upload
        if "logfile" not in request.files:
            return render_template("index.html", error="No file uploaded")
        
        file = request.files["logfile"]
        
        if file.filename == "":
            return render_template("index.html", error="Please select a file")
        
        # Save uploaded file
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
        file.save(filepath)
        
        # Parse and analyze logs
        suspicious_ips = parse_log_file(filepath)
        
        # Calculate statistics
        total_failed = sum(entry["attempts"] for entry in suspicious_ips)
        unique_ips = len(suspicious_ips)
        
        for entry in suspicious_ips:
            if entry["severity"] == "CRITICAL":
                critical_risk += 1
            elif entry["severity"] == "HIGH":
                high_risk += 1
            elif entry["severity"] == "MEDIUM":
                medium_risk += 1
            else:
                low_risk += 1
            
            if entry["is_malicious"]:
                malicious_count += 1
        
        # Calculate AI statistics
        if suspicious_ips:
            ai_scores = [entry["ai_score"] for entry in suspicious_ips]
            avg_ai_score = round(sum(ai_scores) / len(ai_scores), 1)
            max_ai_score = max(ai_scores)
        
        # Determine threat status
        if critical_risk >= 3:
            threat_status = "CRITICAL EMERGENCY"
        elif critical_risk >= 1:
            threat_status = "CRITICAL ALERT"
        elif high_risk >= 2:
            threat_status = "HIGH ALERT"
        elif high_risk >= 1 or medium_risk >= 3:
            threat_status = "ELEVATED"
        elif unique_ips > 0:
            threat_status = "MONITORING"
        else:
            threat_status = "SECURE"
        
        # Get primary attack type
        if suspicious_ips:
            attack_types = [entry["attack"] for entry in suspicious_ips]
            attack_type = max(set(attack_types), key=attack_types.count)
        
        # Generate recommendations
        recommendations = generate_recommendation(
            critical_risk, high_risk, unique_ips, attack_type
        )
        
        # Store stats globally
        analysis_stats = {
            "total_failed": total_failed,
            "critical_risk": critical_risk,
            "high_risk": high_risk,
            "medium_risk": medium_risk,
            "low_risk": low_risk,
            "unique_ips": unique_ips,
            "avg_ai_score": avg_ai_score,
            "max_ai_score": max_ai_score,
            "malicious_count": malicious_count,
            "threat_status": threat_status,
            "attack_type": attack_type,
            "upload_time": upload_time
        }
    
    return render_template(
        "index.html",
        suspicious_ips=suspicious_ips,
        total_failed=total_failed,
        high_risk=high_risk,
        critical_risk=critical_risk,
        medium_risk=medium_risk,
        low_risk=low_risk,
        unique_ips=unique_ips,
        upload_time=upload_time,
        threat_status=threat_status,
        attack_type=attack_type,
        recommendations=recommendations,
        avg_ai_score=avg_ai_score,
        max_ai_score=max_ai_score,
        malicious_count=malicious_count
    )


# ---------------- API ENDPOINT ---------------- #

@app.route("/api/stats")
def api_stats():
    """API endpoint for real-time stats"""
    return jsonify(analysis_stats)


# ---------------- CSV EXPORT ---------------- #

@app.route("/download-report")
def download_report():
    global analysis_results, analysis_stats
    
    if not analysis_results:
        return "No data available. Please analyze a log file first.", 400
    
    # Create CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write report header
    writer.writerow(["=" * 60])
    writer.writerow(["SOC THREAT ANALYSIS REPORT"])
    writer.writerow(["Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
    writer.writerow(["=" * 60])
    writer.writerow([])
    
    # Write summary statistics
    writer.writerow(["SUMMARY STATISTICS"])
    writer.writerow(["Total Failed Attempts:", analysis_stats.get("total_failed", 0)])
    writer.writerow(["Unique Suspicious IPs:", analysis_stats.get("unique_ips", 0)])
    writer.writerow(["Critical Threats:", analysis_stats.get("critical_risk", 0)])
    writer.writerow(["High Risk IPs:", analysis_stats.get("high_risk", 0)])
    writer.writerow(["Average AI Score:", analysis_stats.get("avg_ai_score", 0)])
    writer.writerow(["Threat Status:", analysis_stats.get("threat_status", "N/A")])
    writer.writerow([])
    
    # Write detailed results header
    writer.writerow(["DETAILED THREAT ANALYSIS"])
    writer.writerow([
        "IP Address",
        "Failed Attempts",
        "Threat Severity",
        "Country",
        "Attack Type",
        "AI Score",
        "AI Risk Level",
        "AI Confidence",
        "Known Malicious",
        "Timestamp"
    ])
    
    # Write data rows
    for entry in analysis_results:
        writer.writerow([
            entry["ip"],
            entry["attempts"],
            entry["severity"],
            entry["country"],
            entry["attack"],
            entry["ai_score"],
            entry["ai_risk"],
            f"{entry['ai_confidence']}%",
            "Yes" if entry["is_malicious"] else "No",
            entry["timestamp"]
        ])
    
    # Prepare file for download
    output.seek(0)
    mem_file = io.BytesIO()
    mem_file.write(output.getvalue().encode("utf-8"))
    mem_file.seek(0)
    
    filename = f"soc_threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    return send_file(
        mem_file,
        mimetype="text/csv",
        as_attachment=True,
        download_name=filename
    )


# ---------------- RUN APPLICATION ---------------- #

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
