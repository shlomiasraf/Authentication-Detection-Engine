# Authentication Detection Engine

## Overview

This project demonstrates authentication-focused and network-based detection engineering techniques across Linux security telemetry environments and structured SQL telemetry tables.

The goal of this lab is to simulate realistic attacker behavior and implement detection logic based on authentication events collected from Linux systems, Kerberos telemetry, NTLM authentication activity, and DNS query behavior.

The detectors correlate:

- failed authentication attempts
- successful login activity
- privilege escalation behavior
- persistence indicators
- geographic login anomalies
- multi-stage attack chains
- Kerberos TGT anomaly patterns
- NTLM brute-force authentication sequences
- DNS exfiltration indicators
- DNS query burst anomalies
- suspicious TXT DNS activity

This project reflects hands-on experience with:

- Linux authentication logs (auth.log)
- Kerberos authentication telemetry
- NTLM authentication telemetry
- DNS telemetry analysis
- SQL-based telemetry normalization
- pandas-based detection correlation
- behavioral authentication analytics
- privilege escalation detection
- persistence detection logic
- network anomaly detection techniques

---

## Detection Coverage

### Linux — Brute Force Detection

Detects:

multiple failed login attempts from the same IP address  
repeated authentication failures within a defined time window  

File:

detectors/brute_force_detector.py

Telemetry source:

auth_events (parsed from Linux auth.log)

---

### Linux — Password Spray Detection

Detects:

authentication attempts using one password across multiple user accounts from the same source IP  

File:

detectors/password_spray_detector.py

Telemetry source:

auth_events

---

### Linux — Foreign Login Detection

Detects:

authentication attempts originating from unusual geographic locations  

Uses IP enrichment logic to identify suspicious login origins.

File:

detectors/foreign_login_detector.py

Telemetry source:

auth_events + IP enrichment

---

### Linux — SSH Attack Chain Detection

Detects a realistic attacker sequence:

Invalid login attempts  
→ Successful login  
→ sudo privilege escalation  
→ New user creation  

This represents credential compromise followed by privilege escalation and persistence establishment.

File:

detectors/ssh_attack_chain_detector.py

Telemetry source:

auth_events

Notebook correlation workflow:

linux_auth_attack_chain_detector.ipynb

Output:

outputs/alerts_from_linux_auth.json

---

### Kerberos — TGT Brute-Force Success Pattern Detection

Detects:

multiple Kerberos authentication failures followed by successful TGT request activity within a defined time window.

This behavior may indicate password guessing or credential brute-force activity against domain authentication services.

File:

kerberos_tgt_anomaly_detector.ipynb

Telemetry source:

kerberos_events

Output:

outputs/alerts_from_kerberos_detector.json

---

### NTLM — Brute-Force Authentication Detection

Detects:

multiple failed NTLM authentication attempts followed by successful authentication from the same source IP within a short time window.

This represents credential brute-force activity targeting NTLM authentication workflows.

File:

ntlm_bruteforce_detector.ipynb

Telemetry source:

ntlm_events

Output:

outputs/alerts_from_ntlm_detector.json

---

### DNS — Exfiltration & Query Anomaly Detection

Detects:

suspicious long DNS query domains  
DNS burst query activity within short time windows  
TXT record queries associated with command-and-control communication patterns  

These behaviors may indicate DNS-based data exfiltration or malware beaconing activity.

File:

dns_anomaly_detector.ipynb

Telemetry source:

dns_events

Output:

outputs/alerts_from_dns_detector.json

---

### Jupyter Detection Workflow

Security telemetry is ingested from SQL security tables using SQLAlchemy:

SELECT * FROM auth_events  
SELECT * FROM kerberos_events  
SELECT * FROM ntlm_events  
SELECT * FROM dns_events  

Datasets are analyzed using pandas to identify suspicious authentication and network behavior such as:

repeated failed login attempts from the same IP  
failed-to-success authentication transitions  
Kerberos TGT anomaly sequences  
NTLM brute-force authentication bursts  
DNS exfiltration indicators  
DNS query burst anomalies  

Example correlation logic implemented in notebooks:

failed ×3  
→ success  
→ sudo  
→ create_user  

Alerts are generated and exported as structured JSON output.

---

### Detection Pipeline

The detection workflow simulates a simplified SIEM-style authentication and network telemetry pipeline:

Linux auth.log  
→ parsing into structured telemetry  
→ SQL security tables  
(auth_events, kerberos_events, ntlm_events, dns_events)  
→ pandas detection correlation  
→ JSON alert generation  

This reflects a realistic multi-source telemetry detection workflow.

---

### Sample Logs

Example telemetry datasets are included:

logs/linux_auth_attack.log  
logs/detection_practice_logs.json  
logs/detection_time_logs.json  
logs/impossible_travel_logs.json  
logs/sample_security_logs.json  

These allow running detectors locally without requiring external infrastructure.

---

### Example Alert Output

Example correlated attack-chain alert:

failed login ×3  
→ successful login  
→ sudo execution  
→ create_user event  

Example output:

outputs/alerts.json

Additional structured detector outputs:

outputs/alerts_from_linux_auth.json  
outputs/alerts_from_kerberos_detector.json  
outputs/alerts_from_ntlm_detector.json  
outputs/alerts_from_dns_detector.json

---

### Skills Demonstrated

This lab demonstrates practical detection engineering skills:

- authentication telemetry parsing
- Kerberos authentication anomaly detection
- NTLM authentication correlation detection
- DNS telemetry behavioral analytics
- SQL-based security data normalization
- pandas-based behavioral detection logic
- time-window correlation detection
- attack-chain sequence reconstruction
- privilege escalation detection
- persistence detection techniques
- network anomaly detection logic
- modular Python detector development
- structured JSON alert generation
