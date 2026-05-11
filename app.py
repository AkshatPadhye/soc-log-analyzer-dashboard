from flask import Flask, render_template, request
from collections import Counter
import os
from datetime import datetime

app = Flask(__name__)

# ---------------- CONFIGURATION ---------------- #

UPLOAD_FOLDER = "uploads"

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ---------------- MAIN ROUTE ---------------- #

@app.route("/", methods=["GET", "POST"])

def index():

    suspicious_ips = []

    total_failed = 0

    high_risk = 0

    critical_risk = 0

    unique_ips = 0

    threat_status = "STABLE"

    upload_time = None

    attack_type = "Brute Force Attack Detection"

    if request.method == "POST":

        # File validation

        if "logfile" not in request.files:

            return "No file uploaded"

        file = request.files["logfile"]

        if file.filename == "":

            return "Please select a file"

        # Save uploaded file

        filepath = os.path.join(
            app.config["UPLOAD_FOLDER"],
            file.filename
        )

        file.save(filepath)

        # Read log file

        with open(filepath, "r") as f:

            logs = f.readlines()

        failed_ips = []

        # Analyze logs

        for line in logs:

            if "Failed" in line:

                ip = line.strip().split()[-1]

                failed_ips.append(ip)

        # Count failed login attempts

        count = Counter(failed_ips)

        total_failed = sum(count.values())

        unique_ips = len(count)

        # Threat analysis

        for ip, attempts in count.items():

            # Severity classification

            if attempts >= 5:

                severity = "CRITICAL"

                critical_risk += 1

            elif attempts >= 3:

                severity = "HIGH"

                high_risk += 1

            else:

                severity = "MEDIUM"

            # Store results

            suspicious_ips.append({

                "ip": ip,

                "attempts": attempts,

                "severity": severity

            })

        # Threat condition

        if critical_risk >= 2:

            threat_status = "CRITICAL"

        elif high_risk >= 2:

            threat_status = "HIGH ALERT"

        else:

            threat_status = "STABLE"

        # Upload timestamp

        upload_time = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    # Render dashboard

    return render_template(

        "index.html",

        suspicious_ips=suspicious_ips,

        total_failed=total_failed,

        high_risk=high_risk,

        critical_risk=critical_risk,

        unique_ips=unique_ips,

        threat_status=threat_status,

        attack_type=attack_type,

        upload_time=upload_time
    )


# ---------------- RUN APP ---------------- #

if __name__ == "__main__":

    app.run(debug=True)