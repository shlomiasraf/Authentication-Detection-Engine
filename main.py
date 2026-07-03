import json
from enrichment.ip_enrichment import get_ip_info
from detectors.foreign_login_detector import detector_foreign_login
from detectors.brute_force_detector import detector_brute_force
from detectors.password_spray_detector import detector_password_spray
from detectors.ssh_attack_chain_detector import detector_attack_chain
from parsing.auth_log_parser import parse_auth_log_line


with open("logs/advanced_detection_logs.json") as f:
    logs = json.load(f)

linux_auth_logs = []

with open("logs/linux_auth_attack.log") as f:
    for line in f:
        parsed = parse_auth_log_line(line)
        if parsed:
            linux_auth_logs.append(parsed)


ip_cache = {}

for log in logs:
    ip = log.get("ip")
    if not ip:
        continue

    if ip not in ip_cache:
        ip_cache[ip] = get_ip_info(ip)

    data = ip_cache[ip]
    log["country"] = data.get("country")
    log["city"] = data.get("city")
    log["org"] = data.get("org")


all_alerts = []

all_alerts.extend(detector_foreign_login(logs))
all_alerts.extend(detector_brute_force(logs))
all_alerts.extend(detector_password_spray(logs))
all_alerts.extend(detector_attack_chain(linux_auth_logs))


for alert in all_alerts:
    print(alert)


output_data = {
    "total_alerts": len(all_alerts),
    "alerts": all_alerts
}

with open("outputs/alerts.json", "w") as f:
    json.dump(output_data, f, indent=2)

print("Alerts saved to outputs/alerts.json")