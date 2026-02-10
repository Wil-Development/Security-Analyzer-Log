import re
import sys
import csv
from collections import defaultdict, deque
from datetime import datetime

# -----------------------------
# Settings (tune these)
# -----------------------------
BRUTE_FAIL_THRESHOLD = 3       # brute-force triggers at N fails in window
BRUTE_WINDOW_SECONDS = 120     # brute-force window (e.g., 2 minutes)

COMP_FAIL_THRESHOLD = 3        # "success after failures" triggers if >= N fails before success
COMP_WINDOW_SECONDS = 600      # lookback window before success (e.g., 10 minutes)

# -----------------------------
# Usage: python Analyzer.py <logfile>
# Example: python Analyzer.py Sample.log
# -----------------------------
if len(sys.argv) != 2:
    print("Usage: python Analyzer.py <logfile>")
    sys.exit(1)

log_file = sys.argv[1]

# Syslog-style timestamp at line start: "Feb 10 10:12:01"
TS_RE = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")

# IP after "from "
IP_RE = re.compile(r"from (\d+\.\d+\.\d+\.\d+)")

# Failed and Accepted patterns (SSH-style)
FAILED_RE = re.compile(r"failed password", re.IGNORECASE)
ACCEPTED_RE = re.compile(r"accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)", re.IGNORECASE)

def parse_timestamp(line: str):
    m = TS_RE.search(line)
    if not m:
        return None
    ts_str = m.group(1)  # e.g. "Feb 10 10:12:01"
    ts_str = f"{datetime.now().year} {ts_str}"
    try:
        return datetime.strptime(ts_str, "%Y %b %d %H:%M:%S")
    except ValueError:
        return None

def severity_from_count(count: int) -> str:
    if count >= 13:
        return "CRITICAL"
    if count >= 8:
        return "HIGH"
    if count >= 5:
        return "MEDIUM"
    return "LOW"

def fmt_uk_gmt(dt: datetime) -> str:
    return dt.strftime("%d/%m/%Y %H:%M:%S") + " (GMT)"

# -----------------------------
# Data stores
# -----------------------------
# Brute force: keep recent fail timestamps per IP (sliding window)
fail_times_brute = defaultdict(deque)

# Keep best (highest) brute count window per IP
best_brute = {}  # ip -> {"count": int, "start": dt, "end": dt}

# Compromise detection: keep recent fail timestamps per IP (longer lookback)
fail_times_comp = defaultdict(deque)

# Compromise findings list
# (severity, ip, user, fail_count, first_fail_dt, success_dt)
compromises = []

#Total fail counts per IP (for reporting)
total_fail_counts = defaultdict(int)


# -----------------------------
# Read log file + detect
# -----------------------------
try:
    with open(log_file, "r") as f:
        for line in f:
            ts = parse_timestamp(line)
            if not ts:
                continue

            # 1) Failed password handling
            if FAILED_RE.search(line):
                ipm = IP_RE.search(line)
                if not ipm:
                    continue
                ip = ipm.group(1)
                total_fail_counts[ip] += 1

                # ---- Brute-force window tracking
                dq_b = fail_times_brute[ip]
                dq_b.append(ts)
                while dq_b and (ts - dq_b[0]).total_seconds() > BRUTE_WINDOW_SECONDS:
                    dq_b.popleft()

                # Update best brute window for this IP
                c = len(dq_b)
                if c >= BRUTE_FAIL_THRESHOLD:
                    if (ip not in best_brute) or (c > best_brute[ip]["count"]):
                        best_brute[ip] = {"count": c, "start": dq_b[0], "end": dq_b[-1]}

                # ---- Compromise lookback tracking (longer window)
                dq_c = fail_times_comp[ip]
                dq_c.append(ts)
                while dq_c and (ts - dq_c[0]).total_seconds() > COMP_WINDOW_SECONDS:
                    dq_c.popleft()

                continue

            # 2) Accepted password handling (success after failures)
            am = ACCEPTED_RE.search(line)
            if am:
                user = am.group(1)
                ip = am.group(2)

                dq_c = fail_times_comp[ip]

                # Remove failures outside compromise lookback window (in case IP never failed again)
                while dq_c and (ts - dq_c[0]).total_seconds() > COMP_WINDOW_SECONDS:
                    dq_c.popleft()

                fail_count = len(dq_c)
                if fail_count >= COMP_FAIL_THRESHOLD:
                    # Severity for compromise: push higher because success happened
                    sev = "CRITICAL" if fail_count >= 8 else "HIGH"
                    compromises.append((sev, ip, user, fail_count, dq_c[0], ts))

except FileNotFoundError:
    print(f"File not found: {log_file}")
    sys.exit(1)

# -----------------------------
# Build brute-force alerts list (sorted)
# -----------------------------
brute_alerts = []
for ip, info in best_brute.items():
    sev = severity_from_count(info["count"])
    brute_alerts.append((sev, ip, info["start"], info["end"], info["count"]))

sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
brute_alerts.sort(key=lambda x: (sev_rank[x[0]], x[4]), reverse=True)
compromises.sort(key=lambda x: (sev_rank[x[0]], x[3]), reverse=True)

# -----------------------------
# Print results (UK format)
# -----------------------------
brute_window_label = f"{BRUTE_WINDOW_SECONDS//60} minutes" if BRUTE_WINDOW_SECONDS >= 60 else f"{BRUTE_WINDOW_SECONDS} seconds"
comp_window_label = f"{COMP_WINDOW_SECONDS//60} minutes" if COMP_WINDOW_SECONDS >= 60 else f"{COMP_WINDOW_SECONDS} seconds"

print(f"Brute-force alerts (>= {BRUTE_FAIL_THRESHOLD} fails in {brute_window_label}):")
if not brute_alerts:
    print("None")
else:
    for sev, ip, start, end, count in brute_alerts:
        print(f"{sev} - {ip} - {count} fails between {fmt_uk_gmt(start)} and {fmt_uk_gmt(end)}")

print("")
print(f"Possible compromise alerts (>= {COMP_FAIL_THRESHOLD} fails then SUCCESS within {comp_window_label}):")
if not compromises:
    print("None")
else:
    for sev, ip, user, fail_count, first_fail, success_time in compromises:
        print(f"{sev} - {ip} - Possible compromise: {fail_count} fails then SUCCESS for {user}")
        print(f"      Time: {fmt_uk_gmt(first_fail)} → {fmt_uk_gmt(success_time)}")

print("")
print("Top offending IPs (by total failed attempts):")

top_n = 5
top_ips = sorted(total_fail_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]

if not top_ips:
    print("None")
else:
    for ip, count in top_ips:
        print(f"{ip} - {count} total failed attempts")


# -----------------------------
# Export to CSV (single file)
# -----------------------------
with open("results.csv", "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Finding Type", "Severity", "IP Address", "User", "Count", "Start (UK)", "End (UK)", "Window Seconds"])

    # Brute force rows
    for sev, ip, start, end, count in brute_alerts:
        writer.writerow([
            "Brute Force",
            sev,
            ip,
            "N/A", # No specific user for brute-force alerts
            count,
            fmt_uk_gmt(start),
            fmt_uk_gmt(end),
            BRUTE_WINDOW_SECONDS
        ])

    # Compromise rows
    for sev, ip, user, fail_count, first_fail, success_time in compromises:
        writer.writerow([
            "Success After Failures",
            sev,
            ip,
            user,
            fail_count,
            fmt_uk_gmt(first_fail),
            fmt_uk_gmt(success_time),
            COMP_WINDOW_SECONDS
        ])

        writer.writerow([])
        writer.writerow(["Top Offending IPs"])
        writer.writerow(["IP Address", "Total Failed Attempts"])

        for ip, count in top_ips:
         writer.writerow([ip, count])

print("")
print("Results exported to results.csv")
 

