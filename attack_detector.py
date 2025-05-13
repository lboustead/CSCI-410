import re
from collections import defaultdict

def load_file(path):
    try:
        with open(path, 'r') as f:
            return f.readlines()
    except Exception as e:
        print(f"Error: {e}")
        return []


def analyze_log(lines):
    events = []
    for line in lines:
        ip = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
        event = {
            "line": line.strip(),
            "ip": ip.group() if ip else None,
            "failed_login": "failed login" in line.lower(),
            "timestamp": line[:19]
        }
        events.append(event)
    return events


def known_pattern_detection(events, threshold=5):
    failed_counts = defaultdict(int)
    for e in events:
        if e["failed_login"] and e["ip"]:
            failed_counts[e["ip"]] += 1
    flagged = {ip: count for ip, count in failed_counts.items() if count >= threshold}
    return {"brute_force": flagged}


def pattern_prototype_detection(events):
    ip_usernames = defaultdict(set)
    for e in events:
        match = re.search(r'user\s+(\w+)', e["line"], re.IGNORECASE)
        if match and e["ip"]:
            ip_usernames[e["ip"]].add(match.group(1).lower())
    anomalies = {ip: users for ip, users in ip_usernames.items() if len(users) > 3}
    return {"multi_user_access": anomalies}


def attack_detection(known, prototype):
    report = []
    if known["brute_force"]:
        report.append("Brute-force attack detected from:")
        for ip, count in known["brute_force"].items():
            report.append(f" - {ip}: {count} failed logins")
    if prototype["multi_user_access"]:
        report.append("Prototype anomaly detected (multi-user access) from:")
        for ip, users in prototype["multi_user_access"].items():
            report.append(f" - {ip}: accessed {len(users)} users ({', '.join(users)})")
    if not report:
        report.append("No suspicious activity detected.")
    return report


def main():
    # Call all functions in order
    path = input("Enter path to log file: ")
    log_lines = load_file(path)
    parsed_data = analyze_log(log_lines)
    known_results = known_pattern_detection(parsed_data)
    proto_results = pattern_prototype_detection(parsed_data)
    attack_report = attack_detection(known_results, proto_results)

    print("\n--- Final Report ---")
    for entry in attack_report:
        print(entry)

if __name__ == "__main__":
    main()
