from collections import defaultdict


def detect_threats(parsed_logs):

    detected_threats = []

    failed_login_counter = defaultdict(int)

    for log in parsed_logs:

        attack_type = "Normal Activity"
        severity = "Low"
        risk_score = 10
        recommendation = "No action required."

        message = log["message"].lower()

        ip = log["ip_address"]

        # -------------------------
        # Failed Login Detection
        # -------------------------

        if "login failed" in message or (
            log["event_type"] == "Authentication"
            and log["status"] == "Failed"
        ):

            failed_login_counter[ip] += 1

            attack_type = "Failed Login"
            severity = "Medium"
            risk_score = 40
            recommendation = "Monitor failed login attempts."

            # Brute Force Detection

            if failed_login_counter[ip] >= 3:

                attack_type = "Brute Force Attack"
                severity = "High"
                risk_score = 80
                recommendation = "Block IP and enable MFA."

        # -------------------------
        # SQL Injection
        # -------------------------

        elif "sql injection" in message:

            attack_type = "SQL Injection"

            severity = "Critical"

            risk_score = 95

            recommendation = (
                "Inspect web server logs and block malicious requests."
            )

        # -------------------------
        # Malware
        # -------------------------

        elif "malware" in message:

            attack_type = "Malware"

            severity = "Critical"

            risk_score = 100

            recommendation = (
                "Isolate infected system immediately."
            )

        # -------------------------
        # Unauthorized Access
        # -------------------------

        elif "unauthorized" in message:

            attack_type = "Unauthorized Access"

            severity = "High"

            risk_score = 75

            recommendation = (
                "Review account permissions and investigate."
            )

        detected_threats.append({

            "timestamp": log["timestamp"],

            "ip_address": ip,

            "username": log["username"],

            "attack_type": attack_type,

            "severity": severity,

            "risk_score": risk_score,

            "recommendation": recommendation

        })

    return detected_threats