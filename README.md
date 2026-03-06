# Security Log Analyzer

## Overview

Security Log Analyzer is a Python-based security tool designed to analyse authentication logs and identify suspicious behaviour such as brute-force login attempts and potential account compromise.

The tool parses log files, detects repeated failed login attempts, and identifies patterns where multiple failed logins are followed by a successful authentication. These behaviours are commonly associated with credential-based attacks.

This project demonstrates practical Security Operations Centre (SOC) skills including log analysis, detection logic development, and automated investigation reporting.

---

## Security Problem

Brute-force and credential stuffing attacks are common techniques used by attackers to gain unauthorised access to systems. Detecting these attacks early is important for protecting user accounts and preventing data breaches.

Manually reviewing large log files can be slow and inefficient. This tool automates the process by analysing authentication logs and highlighting suspicious activity.

---

## Features

- Detects repeated failed login attempts from the same IP address
- Identifies successful logins that occur after multiple failed attempts
- Highlights potential brute-force activity
- Calculates alert severity based on behaviour patterns
- Exports investigation findings to CSV for reporting and analysis

---

## Detection Logic

The script analyses authentication logs and looks for patterns such as:

- Multiple failed login attempts within a short time window
- Failed login attempts followed by a successful login
- IP addresses generating suspicious authentication behaviour

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

Navigate into the project folder:
Analyzer.py





