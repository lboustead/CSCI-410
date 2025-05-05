import re
from collections import defaultdict

def load_log_file(path):
    try:
        with open(path, 'r') as file:
            return file.readlines()
    except FileNotFoundError:
        print("File not found.")
        return []

def analyze_log(lines):
    failed_login_pattern = re.compile(r"Failed login", re.IGNORECASE)
    ip_attempts = defaultdict(int)

    for line in lines:
        if failed_login_pattern.search(line):
            ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
            if ip_match:
                ip = ip_match.group()
                ip_attempts[ip] += 1

    return ip_attempts

def detect_attacks(ip_attempts, threshold=5):
    suspicious_ips = {ip: count for ip, count in ip_attempts.items() if count >= threshold}
    return suspicious_ips

def main():
    path = input("Enter path to log file: ")
    log_lines = load_log_file(path)
    ip_attempts = analyze_log(log_lines)
    suspicious_ips = detect_attacks(ip_attempts)

    print("\n--- Analysis Result ---")
    if suspicious_ips:
        print("Possible brute-force attacks detected from:")
        for ip, count in suspicious_ips.items():
            print(f"{ip} — {count} failed attempts")
    else:
        print("No attack patterns detected.")

if __name__ == "__main__":
    main()
