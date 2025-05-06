def determine_attack(known, prototype):
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
