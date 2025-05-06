from collections import defaultdict
import re

def detect_prototype_patterns(events):
    ip_usernames = defaultdict(set)

    for e in events:
        match = re.search(r'user\s+(\w+)', e["line"], re.IGNORECASE)
        if match and e["ip"]:
            ip_usernames[e["ip"]].add(match.group(1).lower())

    anomalies = {ip: users for ip, users in ip_usernames.items() if len(users) > 3}
    return {"multi_user_access": anomalies}
