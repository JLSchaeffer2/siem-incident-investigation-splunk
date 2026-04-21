# SIEM Incident Investigation (Splunk)

## Overview
This project documents a full-scale security investigation using Splunk SIEM to analyze a complex attack involving AWS infrastructure, compromised endpoints, and multiple adversary techniques.

The investigation focused on identifying indicators of compromise (IOCs), reconstructing attacker behavior, and determining the overall scope and impact of the incident.

---

## Objective
To investigate suspicious activity across cloud and endpoint environments by analyzing log data, identifying attack patterns, and validating security events through structured SIEM queries.

---

## Tools & Technologies
- Splunk (SIEM)
- AWS CloudTrail Logs
- Sysmon & Windows Event Logs
- osquery (Linux telemetry)
- Network flow & DNS logs
- OSINT (external threat intelligence)

---

## Investigation Highlights

### Cloud & Identity Analysis
- Queried AWS CloudTrail logs to identify active IAM users and API activity  
- Detected API usage without MFA by analyzing nested authentication fields  
- Investigated compromised AWS access keys and validated exposure through log and OSINT correlation  

### Misconfiguration & Data Exposure
- Identified publicly accessible S3 bucket using ACL change events  
- Confirmed unauthorized external interaction with exposed cloud storage  
- Tracked file uploads during the exposure window  

### Endpoint & Cryptomining Detection
- Correlated DNS and endpoint telemetry to detect cryptomining activity  
- Identified sustained high CPU usage tied to browser processes  
- Confirmed communication with known mining domains  

### Credential Compromise & Attacker Activity
- Traced compromised AWS credentials to attacker activity  
- Identified attacker tooling through user agent analysis  
- Detected unauthorized IAM actions and enumeration behavior  

### Malware & Phishing Analysis
- Identified phishing email with macro-enabled attachment  
- Decoded base64 payload to uncover malware details  
- Tracked execution through Sysmon process creation logs  
- Identified initial malicious executable dropped on endpoint  

### Command & Control (C2) Detection
- Detected outbound traffic to malicious IP (45.77.53.176)  
- Decoded obfuscated PowerShell commands (Base64 + Hex)  
- Identified attacker communication endpoint `/admin/get.php`  
- Confirmed compromised hosts communicating with C2 infrastructure  

### Privilege Escalation & Persistence
- Identified Linux privilege escalation via kernel exploit  
- Detected obfuscated command execution and payload staging in `/tmp`  
- Confirmed unauthorized user creation and persistence mechanisms  

---

## Key Findings
- Multi-stage attack involving:
  - Credential compromise  
  - Cloud misconfiguration  
  - Endpoint compromise  
  - Cryptomining activity  
  - Malware execution  
  - Command-and-control communication  

- Confirmed compromise across multiple systems including:
  - Windows endpoints  
  - Linux host with root-level access  

---

## Skills Demonstrated
- SIEM Log Analysis (Splunk)
- Threat Detection & Investigation
- Incident Response Analysis
- Log Correlation (Cloud, Endpoint, Network)
- Pattern Recognition & Anomaly Detection
- OSINT & Threat Intelligence
