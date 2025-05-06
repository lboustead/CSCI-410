import re

def analyze_log(lines):
    events = []
    for line in lines:
        ip = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
        event = {
            "line": line.strip(),
            "ip": ip.group() if ip else None,
            "failed_login": "failed login" in line.lower(),
            "timestamp": line[:19]  # very rough timestamp parsing
        }
        events.append(event)
    return events
