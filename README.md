# Security Log Analyzer

## Overview

Security Log Analyzer is a Python-based detection engineering project designed to identify suspicious authentication behaviour within system log files.

The tool analyses authentication events to detect patterns commonly associated with credential-based attacks, including brute-force login attempts and successful authentication following repeated failed logins.

This project demonstrates practical Security Operations Centre (SOC) skills such as log analysis, behavioural detection logic, and automated investigation reporting.

---

## Security Use Case

Credential attacks such as brute-force and password guessing are common entry points used by attackers to gain unauthorised access to systems.

Security teams rely on log analysis to identify these patterns and respond quickly.

This tool simulates a basic detection workflow used in SOC environments by automatically identifying suspicious authentication activity within log data.

---

## Detection Logic

The analyzer searches for behaviour patterns that may indicate malicious activity, including:

• Multiple failed authentication attempts from the same IP address  
• Rapid login attempts within a short timeframe  
• Successful login events occurring after repeated failures  
• Authentication anomalies associated with potential account compromise  

---

Example detection pattern:
Failed login
Failed login
Failed login
Successful login

This sequence may indicate a brute-force attack where the attacker eventually guesses the correct credentials.

---

## Example Log Format

The script expects logs formatted like the following:

10/02/2026 10:12:01 (GMT) LOGIN FAILED user=john ip=192.168.1.10

10/02/2026 10:12:05 (GMT) LOGIN FAILED user=john ip=192.168.1.10

10/02/2026 10:12:08 (GMT) LOGIN FAILED user=john ip=192.168.1.10

10/02/2026 10:12:15 (GMT) LOGIN SUCCESS user=john ip=192.168.1.10

---

## Installation

Clone the repository:https://github.com/Wil-Development/Security-Analyzer-Log

Navigate into the project directory:

cd Security-Analyzer-Log

Ensure Python is installed

---

## Usage

Run the script with a log file as input:

python analyzer.py sample.log

The script will analyse the log file and output suspicious authentication activity.

Example output:

Suspicious Activity Detected

IP: 192.168.1.10
Failed Attempts: 3
Successful Login After Failures: Yes
Severity: High

---

## CSV Export

Investigation findings can be exported to a CSV file for documentation or further analysis.

Example output file:

results.csv

---

## Investigation Output

Detected events can be exported to a CSV file for documentation or further analysis.

Example fields included in the output:

- Timestamp
- Username
- Source IP Address
- Failed Login Count
- Detection Severity

---

## Technologies Used

- Python
- Log parsing
- Security event analysis
- Behaviour-based detection logic

---

## Skills Demonstrated

This project demonstrates practical cybersecurity capabilities including:

- Security log analysis
- Behavioural detection engineering
- Credential attack detection
- Security investigation automation
- Threat detection logic development

---

## Potential Improvements

Future improvements could include:

- Real-time log monitoring
- Integration with SIEM platforms
- IP reputation enrichment using threat intelligence
- Detection of additional attack techniques

---

## Author

Wilson Bonaventura  
Cybersecurity / SOC Analyst












