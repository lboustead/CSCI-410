from collections import defaultdict

def detect_known_patterns(events, threshold=5):
    failed_counts = defaultdict(int)
    for e in events:
        if e["failed_login"] and e["ip"]:
            failed_counts[e["ip"]] += 1

    flagged = {ip: count for ip, count in failed_counts.items() if count >= threshold}
    return {"brute_force": flagged}
