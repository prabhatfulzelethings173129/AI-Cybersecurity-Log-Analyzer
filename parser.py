import re


def parse_logs(log_text):
    """
    Parses cybersecurity logs and extracts useful information.
    Returns a list of dictionaries.
    """

    parsed_logs = []

    # Main log pattern
    log_pattern = re.compile(
        r'(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<level>INFO|WARNING|ERROR|CRITICAL)\s+'
        r'(?P<message>.*)'
    )

    # Regex patterns
    ip_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+)')
    user_pattern = re.compile(r'user\s+(\w+)', re.IGNORECASE)
    port_pattern = re.compile(r'port\s+(\d+)', re.IGNORECASE)

    for line in log_text.splitlines():

        line = line.strip()

        if not line:
            continue

        match = log_pattern.match(line)

        if not match:
            continue

        timestamp = match.group("timestamp")
        level = match.group("level")
        message = match.group("message")

        # Extract IP
        ip_match = ip_pattern.search(message)
        ip = ip_match.group(1) if ip_match else "Unknown"

        # Extract Username
        user_match = user_pattern.search(message)
        username = user_match.group(1) if user_match else "Unknown"

        # Extract Port
        port_match = port_pattern.search(message)
        port = port_match.group(1) if port_match else "N/A"

        # Detect Event Type
        message_lower = message.lower()

        if "login" in message_lower:
            event_type = "Authentication"

        elif "sql injection" in message_lower:
            event_type = "SQL Injection"

        elif "malware" in message_lower:
            event_type = "Malware"

        elif "unauthorized" in message_lower:
            event_type = "Unauthorized Access"

        elif "ddos" in message_lower:
            event_type = "DDoS"

        else:
            event_type = "General"

        # Detect Status
        if "failed" in message_lower:

            status = "Failed"

        elif "success" in message_lower:

            status = "Success"

        else:

            status = "Unknown"

        parsed_logs.append({

            "timestamp": timestamp,

            "level": level,

            "event_type": event_type,

            "status": status,

            "ip_address": ip,

            "username": username,

            "port": port,

            "message": message

        })

    return parsed_logs