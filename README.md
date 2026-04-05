# Security Log Analyzer

> Automated multi-format log analysis and threat detection tool with an interactive HTML dashboard — built as a portfolio project for SOC Analyst roles.

---

## Description

Security Log Analyzer is a Python command-line tool that parses **Windows Security Event Logs**, **Linux auth.log**, and **Apache/Nginx access logs**, automatically detects malicious activity across 11 threat categories, scores findings by severity (LOW / MEDIUM / HIGH / CRITICAL), and generates a self-contained, dark-themed **HTML report** complete with interactive charts, a filterable findings table, and a top suspicious IPs leaderboard. No external Python dependencies are required — the tool runs on the standard library and uses Chart.js (loaded via CDN) for data visualization.

---

## Features

| # | Threat Detection | Severity Range |
|---|-----------------|----------------|
| 1 | **Brute Force Attack** — 5+ failed logins from the same IP within 5 minutes | HIGH / CRITICAL |
| 2 | **Post-Brute-Force Compromise** — successful login detected after brute force | CRITICAL |
| 3 | **Privilege Escalation** — sudo failures and `NOT in sudoers` attempts | MEDIUM / HIGH |
| 4 | **Windows Special Privilege Assignment** — EventID 4672/4673/4674 | MEDIUM |
| 5 | **Port Scan** — 10+ unique destination ports probed in 2 minutes (Windows Firewall EventID 5156) | HIGH |
| 6 | **SQL Injection** — injection patterns detected in HTTP request paths | HIGH / CRITICAL |
| 7 | **Path Traversal** — directory traversal sequences (`../`) in HTTP requests | HIGH |
| 8 | **Admin Panel Probing** — requests to `/admin`, `/wp-admin`, `/phpmyadmin`, etc. | MEDIUM / HIGH |
| 9 | **Malicious Scanner / Tool** — known tool signatures (sqlmap, nikto, wfuzz, etc.) | MEDIUM / HIGH |
| 10 | **Off-Hours Access** — successful logins between 23:00 and 05:00 | MEDIUM / HIGH |
| 11 | **Command Injection** — shell metacharacters and command names in HTTP requests | HIGH / CRITICAL |

### Report Dashboard
- Executive summary with severity metric cards
- Event & threat timeline chart (bar + line overlay)
- Severity distribution doughnut chart
- Threat category breakdown (horizontal bar chart)
- Top 10 suspicious IPs with risk scores
- Filterable, detailed findings table with evidence

---

## Supported Log Formats

**Linux auth.log** (syslog format)
```
Apr  1 23:42:01 prod-web-01 sshd[7001]: Failed password for root from 45.33.32.156 port 43211 ssh2
```

**Apache / Nginx access log** (Combined Log Format)
```
185.220.101.34 - - [01/Apr/2026:13:22:01 +0000] "GET /login?user=admin'-- HTTP/1.1" 200 1243 "-" "sqlmap/1.7.8"
```

**Windows Security Event Log** (pipe-delimited single-line export)
```
2026-04-01 17:33:01 | EventID: 4625 | Account: administrator | Source IP: 198.51.100.200 | Dest Port: 445 | Computer: DC01 | Result: Audit Failure
```

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/osnoko/security-log-analyzer.git
cd security-log-analyzer

# 2. No pip install required — uses Python standard library only
#    Requires Python 3.10+

# 3. Generate sample logs and run a demo analysis
python log_analyzer.py --generate-samples
```

Open `report.html` in any web browser to view the full dashboard.

---

## Usage

```bash
# Demo mode — generates sample_logs.txt and analyzes it
python log_analyzer.py --generate-samples

# Analyze a real log file
python log_analyzer.py /var/log/auth.log

# Specify a custom output path
python log_analyzer.py access.log --output my_report.html

# Mixed-format log (Windows + Linux + Apache in one file)
python log_analyzer.py combined_logs.txt -o combined_report.html
```

---

## Screenshot

> *Open `report.html` in a browser after running to see the live dashboard.*

![Report Dashboard](screenshot.png)

---

## Sample Output

Running against the included `sample_logs.txt` (88 log entries across all three formats):

```
[+] Sample log written: sample_logs.txt
[*] Parsing: sample_logs.txt
[*] Parsed 88 entries  (auth:28  apache:30  windows:30)  - 41 lines skipped
[*] Running threat detection ...

  Findings summary
  ----------------------------------------
  CRITICAL :    1
  HIGH     :    7
  MEDIUM   :    8
  LOW      :    0
  ----------------------------------------
  TOTAL    :   16

[+] Report saved: report.html
```

---

## Technologies Used

| Technology | Purpose |
|------------|---------|
| **Python 3.10+** | Core application, log parsing, threat detection |
| **re (regex)** | Log format parsing and attack signature matching |
| **collections / datetime** | Sliding-window threat detection logic |
| **urllib.parse** | URL decoding before attack pattern matching |
| **Chart.js 4.4** | Interactive timeline, doughnut, and bar charts |
| **HTML5 / CSS3** | Self-contained report with dark theme UI |

No third-party Python packages required.

---

## Project Structure

```
security-log-analyzer/
├── log_analyzer.py     # Main tool — parser, detector, report generator
├── sample_logs.txt     # Realistic multi-format demo log file
├── report.html         # Generated HTML report (open in browser)
└── README.md
```

---

## Author

**Chukwuebuka Okonkwo**
Security Analyst | CompTIA Security+ | ISC2 CC

- GitHub: [github.com/osnoko](https://github.com/osnoko)
- Location: Hamilton, Ontario, Canada

---

## License

This project is open source and available under the [MIT License](LICENSE).
