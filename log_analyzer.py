#!/usr/bin/env python3
"""
Security Log Analyzer — Portfolio Edition
Parses Windows Event Logs, Linux auth.log, and Apache/Nginx access logs.
Detects brute force, privilege escalation, port scans, malicious scanners,
web attacks, and off-hours access. Outputs a professional HTML report.

Usage:
  python log_analyzer.py sample_logs.txt
  python log_analyzer.py /var/log/auth.log --output report.html
  python log_analyzer.py --generate-samples
"""

import re
import sys
import json
import argparse
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
import html as html_lib
from urllib.parse import unquote_plus


# ─── Constants ───────────────────────────────────────────────────────────────

SEVERITY_SCORES = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

SEVERITY_COLORS = {
    "LOW":      "#3b82f6",
    "MEDIUM":   "#f59e0b",
    "HIGH":     "#ef4444",
    "CRITICAL": "#a855f7",
}

MALICIOUS_USER_AGENTS = [
    "sqlmap", "nikto", "nmap", "masscan", "zgrab", "nuclei",
    "dirbuster", "gobuster", "wfuzz", "hydra", "medusa",
    "burpsuite", "acunetix", "nessus", "openvas", "w3af",
    "havij", "pangolin", "libwww-perl", "metasploit",
    "jbrofuzz", "paros", "webinspect", "appscan",
    "skipfish", "zaproxy", "arachni", "commix", "wpscan",
]

# ─── Data Structures ─────────────────────────────────────────────────────────

@dataclass
class LogEntry:
    timestamp:    datetime
    source_ip:    str
    raw_line:     str
    log_format:   str           # "auth", "apache", "windows"
    event_type:   str  = ""
    username:     str  = ""
    src_port:     int  = 0
    dest_port:    int  = 0
    status_code:  int  = 0
    user_agent:   str  = ""
    request_path: str  = ""
    event_id:     int  = 0
    hostname:     str  = ""


@dataclass
class ThreatFinding:
    timestamp:   datetime
    source_ip:   str
    threat_type: str
    severity:    str            # LOW | MEDIUM | HIGH | CRITICAL
    description: str
    evidence:    list = field(default_factory=list)
    score:       int  = 0


# ─── Log Parser ───────────────────────────────────────────────────────────────

class LogParser:
    """Auto-detects and parses Linux auth.log, Apache access log, and
    Windows Security Event Log (pipe-delimited single-line format)."""

    # Apache / Nginx Combined Log Format
    _RE_APACHE = re.compile(
        r'^(\S+)\s+'                         # source IP
        r'\S+\s+\S+\s+'                      # ident, auth user
        r'\[(.+?)\]\s+'                      # [timestamp]
        r'"(\S+)\s+(\S*)\s*\S*"\s+'          # "METHOD path PROTO"
        r'(\d{3})\s+\S+\s+'                  # status bytes
        r'"[^"]*"\s+"([^"]*)"'               # "referer" "user-agent"
    )
    _APACHE_TS = "%d/%b/%Y:%H:%M:%S %z"

    # Windows Security Event Log (pipe-delimited single line)
    _RE_WIN = re.compile(
        r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
        r'\s*\|\s*EventID:\s*(?P<eid>\d+)'
        r'(?:\s*\|\s*Account:\s*(?P<acct>\S+))?'
        r'(?:\s*\|\s*Source IP:\s*(?P<sip>[^\s|]+))?'
        r'(?:\s*\|\s*Dest Port:\s*(?P<dp>\d+))?'
        r'(?:\s*\|\s*Computer:\s*(?P<comp>\S+))?'
        r'(?:\s*\|\s*Result:\s*(?P<res>.+?))?$'
    )
    _WIN_TS = "%Y-%m-%d %H:%M:%S"

    # Linux syslog header (auth.log / syslog)
    _RE_SYSLOG = re.compile(
        r'^(\w{3}\s{1,2}\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(\S+)\s+(\S+?)(?:\[\d+\])?:\s+(.+)$'
    )
    _SYSLOG_TS = "%Y %b %d %H:%M:%S"

    # auth.log sub-patterns
    _RE_SSH_FAIL = re.compile(
        r'Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+) port (\d+)'
    )
    _RE_SSH_OK   = re.compile(
        r'Accepted (?:password|publickey) for (\S+) from (\S+) port (\d+)'
    )
    _RE_SUDO_BAD = re.compile(r'(\S+)\s*:\s*user NOT in sudoers')
    _RE_SUDO_FAIL = re.compile(r'(\S+)\s*:\s*\d+ incorrect password attempt')
    _RE_SUDO_FAIL2 = re.compile(r'authentication failure.*?user=(\S+)')

    def __init__(self, year: int = None):
        self._year = year or datetime.now().year

    def parse_line(self, line: str) -> Optional[LogEntry]:
        line = line.strip()
        if not line or line.startswith('#'):
            return None
        return (
            self._parse_apache(line) or
            self._parse_windows(line) or
            self._parse_syslog(line)
        )

    # ── Apache ──

    def _parse_apache(self, line: str) -> Optional[LogEntry]:
        m = self._RE_APACHE.match(line)
        if not m:
            return None
        ip, ts_raw, method, path, status, ua = m.groups()
        try:
            ts = datetime.strptime(ts_raw, self._APACHE_TS).replace(tzinfo=None)
        except ValueError:
            return None
        return LogEntry(
            timestamp=ts, source_ip=ip, raw_line=line, log_format="apache",
            event_type=f"HTTP_{method}_{status}",
            status_code=int(status), user_agent=ua, request_path=path,
        )

    # ── Windows ──

    def _parse_windows(self, line: str) -> Optional[LogEntry]:
        m = self._RE_WIN.match(line)
        if not m:
            return None
        d = m.groupdict()
        try:
            ts = datetime.strptime(d["ts"], self._WIN_TS)
        except ValueError:
            return None
        return LogEntry(
            timestamp=ts,
            source_ip=d["sip"] or "N/A",
            raw_line=line,
            log_format="windows",
            event_id=int(d["eid"]) if d["eid"] else 0,
            username=d["acct"] or "",
            dest_port=int(d["dp"]) if d["dp"] else 0,
            hostname=d["comp"] or "",
            event_type=d["res"] or "",
        )

    # ── Syslog / auth.log ──

    def _parse_syslog(self, line: str) -> Optional[LogEntry]:
        m = self._RE_SYSLOG.match(line)
        if not m:
            return None
        ts_raw, host, proc, msg = m.groups()
        try:
            ts = datetime.strptime(f"{self._year} {ts_raw.strip()}", self._SYSLOG_TS)
        except ValueError:
            return None

        entry = LogEntry(
            timestamp=ts, source_ip="N/A", raw_line=line,
            log_format="auth", hostname=host,
            event_type=msg[:60],
        )
        self._enrich_syslog(entry, msg)
        return entry

    def _enrich_syslog(self, entry: LogEntry, msg: str):
        for pattern, handler in [
            (self._RE_SSH_FAIL,   self._h_ssh_fail),
            (self._RE_SSH_OK,     self._h_ssh_ok),
            (self._RE_SUDO_BAD,   self._h_sudo_bad),
            (self._RE_SUDO_FAIL,  self._h_sudo_fail),
            (self._RE_SUDO_FAIL2, self._h_sudo_fail2),
        ]:
            hit = pattern.search(msg)
            if hit:
                handler(entry, hit)
                return

    def _h_ssh_fail(self, e: LogEntry, m):
        e.username, e.source_ip, e.src_port = m.group(1), m.group(2), int(m.group(3))
        e.event_type = "SSH_FAILED"

    def _h_ssh_ok(self, e: LogEntry, m):
        e.username, e.source_ip, e.src_port = m.group(1), m.group(2), int(m.group(3))
        e.event_type = "SSH_SUCCESS"

    def _h_sudo_bad(self, e: LogEntry, m):
        e.username = m.group(1)
        e.event_type = "SUDO_NOT_IN_SUDOERS"

    def _h_sudo_fail(self, e: LogEntry, m):
        e.username = m.group(1)
        e.event_type = "SUDO_FAILED"

    def _h_sudo_fail2(self, e: LogEntry, m):
        e.username = m.group(1)
        e.event_type = "SUDO_FAILED"


# ─── Threat Detector ─────────────────────────────────────────────────────────

class ThreatDetector:
    BRUTE_FORCE_WINDOW  = timedelta(minutes=5)
    BRUTE_FORCE_MIN     = 5
    PORT_SCAN_WINDOW    = timedelta(minutes=2)
    PORT_SCAN_MIN_PORTS = 10
    OFF_HOURS_START     = 23   # 11 PM
    OFF_HOURS_END       = 5    #  5 AM

    # Web attack signatures
    _RE_SQLI = re.compile(
        r"union\s+select|select\s+.+\s+from\s|insert\s+into\s|drop\s+table\s|"
        r"or\s+1\s*=\s*1|and\s+1\s*=\s*1|exec\s*\(|xp_cmdshell|"
        r"information_schema|sleep\s*\(|\bcast\s*\(|convert\s*\(|"
        r"benchmark\s*\(|0x[0-9a-f]{4}",
        re.IGNORECASE,
    )
    _RE_TRAVERSAL = re.compile(r'\.\.[/\\]', re.IGNORECASE)
    _RE_CMD_INJ   = re.compile(
        r'[;&|`]\s*(?:cat|ls|whoami|id|passwd|cmd|powershell|bash|sh)\b|'
        r'%3b|%7c|%26',
        re.IGNORECASE,
    )

    def analyze(self, entries: list[LogEntry]) -> list[ThreatFinding]:
        entries = sorted(entries, key=lambda e: e.timestamp)
        findings: list[ThreatFinding] = []
        findings += self._brute_force(entries)
        findings += self._privilege_escalation(entries)
        findings += self._port_scan(entries)
        findings += self._malicious_user_agents(entries)
        findings += self._off_hours_access(entries)
        findings += self._web_attacks(entries)
        findings += self._admin_probing(entries)
        return sorted(findings, key=lambda f: (-SEVERITY_SCORES[f.severity], f.timestamp))

    # ── Brute Force ──

    def _brute_force(self, entries):
        failed_by_ip: dict[str, list[LogEntry]] = defaultdict(list)
        success_times: dict[str, list[datetime]] = defaultdict(list)

        for e in entries:
            ip = e.source_ip
            if ip in ("N/A", "0.0.0.0", "::1", "127.0.0.1"):
                continue
            if e.event_type == "SSH_FAILED" or (e.log_format == "windows" and e.event_id == 4625):
                failed_by_ip[ip].append(e)
            if e.event_type == "SSH_SUCCESS" or (e.log_format == "windows" and e.event_id == 4624):
                success_times[ip].append(e.timestamp)

        findings = []
        for ip, events in failed_by_ip.items():
            used = set()
            for i, anchor in enumerate(events):
                if i in used:
                    continue
                window = [
                    e for j, e in enumerate(events[i:], i)
                    if e.timestamp - anchor.timestamp <= self.BRUTE_FORCE_WINDOW
                ]
                if len(window) < self.BRUTE_FORCE_MIN:
                    continue

                # Check for post-brute-force successful login
                compromised = any(
                    anchor.timestamp <= t <= anchor.timestamp + timedelta(hours=1)
                    for t in success_times.get(ip, [])
                )
                severity = "CRITICAL" if compromised else "HIGH"
                users = sorted({e.username for e in window if e.username})
                desc = (
                    f"{len(window)} failed login attempts in <=5 min"
                    + (" - SUCCESSFUL LOGIN FOLLOWED (possible compromise)" if compromised else "")
                )
                findings.append(ThreatFinding(
                    timestamp=anchor.timestamp,
                    source_ip=ip,
                    threat_type="Brute Force Attack",
                    severity=severity,
                    description=desc,
                    evidence=[
                        f"Attempts in window: {len(window)}",
                        f"Targeted accounts: {', '.join(users) or 'unknown'}",
                        f"Time of first attempt: {anchor.timestamp:%Y-%m-%d %H:%M:%S}",
                        *(["Post-attack login detected - credentials likely compromised"] if compromised else []),
                    ],
                    score=SEVERITY_SCORES[severity] * 10 + len(window),
                ))
                for j, e in enumerate(events[i:], i):
                    if e.timestamp - anchor.timestamp <= self.BRUTE_FORCE_WINDOW:
                        used.add(j)
                break
        return findings

    # ── Privilege Escalation ──

    def _privilege_escalation(self, entries):
        sudo_by_user: dict[str, list[LogEntry]] = defaultdict(list)
        win_priv: list[LogEntry] = []

        for e in entries:
            if e.event_type in ("SUDO_FAILED", "SUDO_NOT_IN_SUDOERS"):
                sudo_by_user[e.username or e.source_ip].append(e)
            if e.log_format == "windows" and e.event_id in (4672, 4673, 4674):
                win_priv.append(e)

        findings = []

        for user, events in sudo_by_user.items():
            first = events[0]
            not_sudoers = [e for e in events if e.event_type == "SUDO_NOT_IN_SUDOERS"]
            if not_sudoers:
                severity = "HIGH"
                desc = f"User '{user}' attempted sudo but is NOT in sudoers ({len(not_sudoers)} attempt(s))"
            else:
                severity = "MEDIUM" if len(events) < 3 else "HIGH"
                desc = f"{len(events)} sudo authentication failure(s) for user '{user}'"
            findings.append(ThreatFinding(
                timestamp=first.timestamp,
                source_ip=first.source_ip,
                threat_type="Privilege Escalation Attempt",
                severity=severity,
                description=desc,
                evidence=[
                    f"Event types: {', '.join(sorted({e.event_type for e in events}))}",
                    f"Occurrences: {len(events)}",
                ],
                score=SEVERITY_SCORES[severity] * 10,
            ))

        if win_priv:
            by_user: dict[str, list[LogEntry]] = defaultdict(list)
            for e in win_priv:
                by_user[e.username or "unknown"].append(e)
            for user, events in by_user.items():
                first = events[0]
                findings.append(ThreatFinding(
                    timestamp=first.timestamp,
                    source_ip=first.source_ip,
                    threat_type="Privilege Escalation Attempt",
                    severity="MEDIUM",
                    description=f"Windows special privilege assigned to '{user}' (EventID {first.event_id})",
                    evidence=[
                        f"EventIDs: {', '.join(str(e.event_id) for e in events)}",
                        f"Computer: {first.hostname}",
                    ],
                    score=20,
                ))
        return findings

    # ── Port Scan ──

    def _port_scan(self, entries):
        # Detected via Windows Filtering Platform events (EventID 5156)
        by_ip: dict[str, list[LogEntry]] = defaultdict(list)
        for e in entries:
            if (e.log_format == "windows"
                    and e.event_id == 5156
                    and e.dest_port > 0
                    and e.source_ip not in ("N/A",)):
                by_ip[e.source_ip].append(e)

        findings = []
        for ip, events in by_ip.items():
            events.sort(key=lambda e: e.timestamp)
            for i, anchor in enumerate(events):
                window = [
                    e for e in events[i:]
                    if e.timestamp - anchor.timestamp <= self.PORT_SCAN_WINDOW
                ]
                unique_ports = sorted({e.dest_port for e in window})
                if len(unique_ports) >= self.PORT_SCAN_MIN_PORTS:
                    findings.append(ThreatFinding(
                        timestamp=anchor.timestamp,
                        source_ip=ip,
                        threat_type="Port Scan Detected",
                        severity="HIGH",
                        description=(
                            f"Probed {len(unique_ports)} unique ports in "
                            f"<={self.PORT_SCAN_WINDOW.seconds // 60} min "
                            f"(Windows Firewall EventID 5156)"
                        ),
                        evidence=[
                            f"Ports: {', '.join(str(p) for p in unique_ports[:20])}"
                            + ("..." if len(unique_ports) > 20 else ""),
                            f"Events in window: {len(window)}",
                            f"Scan started: {anchor.timestamp:%Y-%m-%d %H:%M:%S}",
                        ],
                        score=30 + len(unique_ports),
                    ))
                    break
        return findings

    # ── Malicious User Agents ──

    def _malicious_user_agents(self, entries):
        flagged: dict[tuple, list[LogEntry]] = defaultdict(list)
        for e in entries:
            if not e.user_agent:
                continue
            ua_lower = e.user_agent.lower()
            for sig in MALICIOUS_USER_AGENTS:
                if sig in ua_lower:
                    flagged[(e.source_ip, sig)].append(e)
                    break

        findings = []
        for (ip, sig), events in flagged.items():
            first = events[0]
            severity = "HIGH" if len(events) > 10 else "MEDIUM"
            paths = list(dict.fromkeys(e.request_path for e in events))[:6]
            findings.append(ThreatFinding(
                timestamp=first.timestamp,
                source_ip=ip,
                threat_type="Malicious Scanner / Tool",
                severity=severity,
                description=f"Tool signature '{sig}' detected in {len(events)} request(s)",
                evidence=[
                    f"User-Agent: {first.user_agent[:90]}",
                    f"Requests: {len(events)}",
                    f"Paths sampled: {', '.join(paths)}",
                ],
                score=SEVERITY_SCORES[severity] * 10 + len(events),
            ))
        return findings

    # ── Off-Hours Access ──

    def _off_hours_access(self, entries):
        by_ip: dict[str, list[LogEntry]] = defaultdict(list)
        for e in entries:
            hour = e.timestamp.hour
            if not (hour >= self.OFF_HOURS_START or hour < self.OFF_HOURS_END):
                continue
            is_login = (
                e.event_type == "SSH_SUCCESS"
                or (e.log_format == "windows" and e.event_id == 4624)
            )
            if is_login and e.source_ip not in ("N/A", "127.0.0.1"):
                by_ip[e.source_ip].append(e)

        findings = []
        for ip, events in by_ip.items():
            first = events[0]
            users = sorted({e.username for e in events if e.username})
            severity = "HIGH" if len(events) >= 3 else "MEDIUM"
            findings.append(ThreatFinding(
                timestamp=first.timestamp,
                source_ip=ip,
                threat_type="Off-Hours Access",
                severity=severity,
                description=(
                    f"{len(events)} successful login(s) during off-hours (23:00-05:00)"
                    + (f" as {', '.join(users)}" if users else "")
                ),
                evidence=[
                    f"Login times: {', '.join(e.timestamp.strftime('%H:%M') for e in events[:6])}",
                    f"Users: {', '.join(users) or 'N/A'}",
                    f"Source: {ip}",
                ],
                score=SEVERITY_SCORES[severity] * 10,
            ))
        return findings

    # ── Web Attacks ──

    def _web_attacks(self, entries):
        buckets: dict[tuple, list[LogEntry]] = defaultdict(list)
        for e in entries:
            if not e.request_path:
                continue
            decoded = unquote_plus(e.request_path)
            if self._RE_SQLI.search(decoded):
                buckets[(e.source_ip, "SQL Injection")].append(e)
            if self._RE_TRAVERSAL.search(decoded):
                buckets[(e.source_ip, "Path Traversal")].append(e)
            if self._RE_CMD_INJ.search(decoded):
                buckets[(e.source_ip, "Command Injection")].append(e)

        findings = []
        for (ip, attack), events in buckets.items():
            first = events[0]
            severity = "CRITICAL" if len(events) > 5 else "HIGH"
            findings.append(ThreatFinding(
                timestamp=first.timestamp,
                source_ip=ip,
                threat_type=f"Web Attack: {attack}",
                severity=severity,
                description=f"{len(events)} {attack} attempt(s) detected in HTTP request paths",
                evidence=[
                    f"Sample: {events[0].request_path[:100]}",
                    f"Attempts: {len(events)}",
                ],
                score=SEVERITY_SCORES[severity] * 10 + len(events),
            ))
        return findings

    # ── Admin Panel Probing ──

    def _admin_probing(self, entries):
        ADMIN_PATHS = ("/admin", "/wp-admin", "/administrator", "/phpmyadmin",
                       "/manager", "/cpanel", "/wp-login", "/xmlrpc")
        by_ip: dict[str, list[LogEntry]] = defaultdict(list)
        for e in entries:
            if not e.request_path:
                continue
            path_lower = e.request_path.lower()
            if any(path_lower.startswith(p) for p in ADMIN_PATHS):
                by_ip[e.source_ip].append(e)

        findings = []
        for ip, events in by_ip.items():
            first = events[0]
            paths = list(dict.fromkeys(e.request_path for e in events))[:8]
            severity = "HIGH" if len(paths) >= 3 else "MEDIUM"
            findings.append(ThreatFinding(
                timestamp=first.timestamp,
                source_ip=ip,
                threat_type="Admin Panel Probing",
                severity=severity,
                description=f"Attempted access to {len(paths)} admin/management path(s)",
                evidence=[
                    f"Paths: {', '.join(paths)}",
                    f"Total requests: {len(events)}",
                ],
                score=SEVERITY_SCORES[severity] * 10 + len(paths),
            ))
        return findings


# ─── HTML Style (static — no Python interpolation needed) ─────────────────────

_HTML_STYLE = """
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: #0a0e1a; color: #c9d1e0; min-height: 100vh;
        }
        /* ── Header ── */
        .hdr {
            background: linear-gradient(135deg, #0d1117 0%, #161b27 60%, #0d1117 100%);
            border-bottom: 1px solid #21262d;
            padding: 20px 40px;
            display: flex; align-items: center; justify-content: space-between;
        }
        .hdr-left { display: flex; align-items: center; gap: 14px; }
        .hdr-icon {
            width: 46px; height: 46px;
            background: linear-gradient(135deg, #ef4444, #a855f7);
            border-radius: 10px;
            display: flex; align-items: center; justify-content: center;
            font-size: 22px; flex-shrink: 0;
        }
        .hdr h1 { font-size: 1.35rem; font-weight: 700; color: #e6edf3; letter-spacing: -.02em; }
        .hdr-sub { font-size: .75rem; color: #7d8590; margin-top: 2px; }
        .hdr-meta { text-align: right; font-size: .76rem; color: #7d8590; line-height: 1.7; }
        .hdr-meta strong { color: #c9d1e0; }
        /* ── Risk Banner ── */
        .risk-banner {
            padding: 12px 40px; display: flex; align-items: center; gap: 10px;
            font-size: .85rem;
        }
        .risk-badge {
            padding: 3px 11px; border-radius: 4px;
            font-weight: 700; font-size: .78rem; letter-spacing: .06em; color: #fff;
        }
        /* ── Container ── */
        .wrap { max-width: 1440px; margin: 0 auto; padding: 28px 40px; }
        /* ── Metric Cards ── */
        .metrics { display: grid; grid-template-columns: repeat(auto-fit,minmax(160px,1fr)); gap: 14px; margin-bottom: 28px; }
        .card {
            background: #161b27; border: 1px solid #21262d; border-radius: 10px;
            padding: 18px 20px; position: relative; overflow: hidden;
            transition: border-color .15s;
        }
        .card:hover { border-color: #30363d; }
        .card::before { content:''; position:absolute; top:0; left:0; right:0; height:3px; background: var(--ac); }
        .card-lbl { font-size: .68rem; text-transform: uppercase; letter-spacing: .08em; color: #7d8590; margin-bottom: 6px; }
        .card-val { font-size: 2rem; font-weight: 700; color: var(--ac); line-height: 1; }
        .card-desc { font-size: .7rem; color: #7d8590; margin-top: 5px; }
        /* ── Charts ── */
        .charts { display: grid; grid-template-columns: 2fr 1fr 1fr; gap: 14px; margin-bottom: 28px; }
        @media(max-width:1100px) { .charts { grid-template-columns: 1fr 1fr; } }
        @media(max-width:700px)  { .charts { grid-template-columns: 1fr; } }
        .chart-box {
            background: #161b27; border: 1px solid #21262d; border-radius: 10px; padding: 18px;
        }
        .chart-box.span-full { grid-column: 1 / -1; }
        .chart-lbl { font-size: .7rem; font-weight: 600; color: #8b949e; text-transform: uppercase; letter-spacing: .07em; margin-bottom: 14px; }
        .ch { position: relative; height: 200px; }
        /* ── Table wrapper ── */
        .tbl-card {
            background: #161b27; border: 1px solid #21262d;
            border-radius: 10px; overflow: hidden; margin-bottom: 28px;
        }
        .tbl-hdr {
            padding: 14px 18px; border-bottom: 1px solid #21262d;
            display: flex; align-items: center; justify-content: space-between;
        }
        .tbl-title { font-size: .88rem; font-weight: 600; color: #e6edf3; }
        .tbl-count {
            background: #21262d; padding: 2px 9px;
            border-radius: 20px; font-size: .72rem; color: #8b949e;
        }
        .tbl-scroll { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; font-size: .8rem; }
        thead th {
            background: #0d1117; padding: 9px 14px; text-align: left;
            font-size: .68rem; text-transform: uppercase; letter-spacing: .06em;
            color: #7d8590; font-weight: 600; white-space: nowrap;
        }
        tbody tr { border-bottom: 1px solid #0d1117; transition: background .1s; }
        tbody tr:hover { background: #1c2333; }
        tbody td { padding: 9px 14px; vertical-align: top; }
        td.ts  { font-family: monospace; font-size: .75rem; color: #8b949e; white-space: nowrap; }
        td.ip  { font-family: monospace; color: #79c0ff; white-space: nowrap; }
        td.rnk { font-weight: 700; color: #7d8590; width: 36px; }
        td.ev  { font-size: .72rem; color: #8b949e; font-family: monospace; }
        .badge {
            display: inline-block; padding: 2px 8px; border-radius: 4px;
            font-size: .67rem; font-weight: 700; letter-spacing: .06em; color: #fff;
        }
        /* ── Score bar ── */
        .sbar { display: flex; align-items: center; gap: 7px; min-width: 110px; }
        .sbar-fill { height: 5px; border-radius: 3px; min-width: 3px; }
        .sbar-val { font-size: .72rem; color: #8b949e; white-space: nowrap; }
        /* ── Filter ── */
        .filters {
            padding: 10px 18px; border-bottom: 1px solid #21262d;
            display: flex; gap: 7px; flex-wrap: wrap; align-items: center;
        }
        .f-lbl { font-size: .7rem; color: #7d8590; margin-right: 2px; }
        .fbtn {
            background: transparent; border: 1px solid #30363d; color: #8b949e;
            padding: 3px 11px; border-radius: 20px; font-size: .72rem;
            cursor: pointer; transition: all .15s;
        }
        .fbtn:hover { color: #c9d1e0; border-color: #484f58; }
        .fbtn.on-all      { color: #e6edf3;  border-color: #e6edf3;  background: #e6edf31a; }
        .fbtn.on-critical { color: #a855f7;  border-color: #a855f7;  background: #a855f71a; }
        .fbtn.on-high     { color: #ef4444;  border-color: #ef4444;  background: #ef44441a; }
        .fbtn.on-medium   { color: #f59e0b;  border-color: #f59e0b;  background: #f59e0b1a; }
        .fbtn.on-low      { color: #3b82f6;  border-color: #3b82f6;  background: #3b82f61a; }
        /* ── Footer ── */
        footer { text-align: center; padding: 28px; color: #484f58; font-size: .72rem; border-top: 1px solid #21262d; }
        .empty { padding: 40px; text-align: center; color: #484f58; }
"""


# ─── Report Generator ────────────────────────────────────────────────────────

class ReportGenerator:

    def generate(
        self,
        findings: list[ThreatFinding],
        entries:  list[LogEntry],
        log_file: str,
        out_path: str = "report.html",
    ) -> str:
        sev_counts    = Counter(f.severity for f in findings)
        threat_counts = Counter(f.threat_type for f in findings)

        # Top suspicious IPs
        ip_score = defaultdict(int)
        ip_hits  = defaultdict(int)
        for f in findings:
            if f.source_ip not in ("N/A", "0.0.0.0", "127.0.0.1"):
                ip_score[f.source_ip] += f.score
                ip_hits[f.source_ip]  += 1
        top_ips = sorted(ip_score.items(), key=lambda x: -x[1])[:10]

        # Timeline — events per hour slot (up to 48 slots)
        hour_counts   = Counter(e.timestamp.strftime("%m-%d %H:00") for e in entries)
        finding_hours = Counter(f.timestamp.strftime("%m-%d %H:00") for f in findings)
        tl_labels = sorted(hour_counts.keys())[-48:]
        tl_events = [hour_counts[h]   for h in tl_labels]
        tl_threats= [finding_hours.get(h, 0) for h in tl_labels]

        html = self._render(
            findings, entries, log_file,
            sev_counts, threat_counts,
            top_ips, ip_hits,
            tl_labels, tl_events, tl_threats,
        )
        Path(out_path).write_text(html, encoding="utf-8")
        return out_path

    def _render(self, findings, entries, log_file,
                sev_counts, threat_counts,
                top_ips, ip_hits,
                tl_labels, tl_events, tl_threats):

        n_total    = len(findings)
        n_entries  = len(entries)
        n_critical = sev_counts.get("CRITICAL", 0)
        n_high     = sev_counts.get("HIGH",     0)
        n_medium   = sev_counts.get("MEDIUM",   0)
        n_low      = sev_counts.get("LOW",      0)
        generated  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if   n_critical: risk, risk_color = "CRITICAL", "#a855f7"
        elif n_high:     risk, risk_color = "HIGH",     "#ef4444"
        elif n_medium:   risk, risk_color = "MEDIUM",   "#f59e0b"
        else:            risk, risk_color = "LOW",      "#3b82f6"

        # ── Chart data ──
        tl_json  = json.dumps(tl_labels)
        te_json  = json.dumps(tl_events)
        tt_json  = json.dumps(tl_threats)
        sev_data = json.dumps([n_critical, n_high, n_medium, n_low])
        threat_items = threat_counts.most_common(8)
        th_labels = json.dumps([t[0] for t in threat_items])
        th_data   = json.dumps([t[1] for t in threat_items])

        # ── Table rows: findings ──
        finding_rows = ""
        for f in findings[:500]:
            c = SEVERITY_COLORS.get(f.severity, "#888")
            ev_html = "<br>".join(html_lib.escape(str(x)) for x in f.evidence)
            finding_rows += (
                f"<tr data-sev='{f.severity}'>"
                f"<td class='ts'>{f.timestamp:%Y-%m-%d %H:%M:%S}</td>"
                f"<td class='ip'>{html_lib.escape(f.source_ip)}</td>"
                f"<td>{html_lib.escape(f.threat_type)}</td>"
                f"<td><span class='badge' style='background:{c}'>{f.severity}</span></td>"
                f"<td>{html_lib.escape(f.description)}</td>"
                f"<td class='ev'>{ev_html}</td>"
                "</tr>"
            )

        # ── Table rows: top IPs ──
        ip_rows = ""
        for rank, (ip, score) in enumerate(top_ips, 1):
            ip_f = [f for f in findings if f.source_ip == ip]
            worst = max((f.severity for f in ip_f), key=lambda s: SEVERITY_SCORES.get(s, 0), default="LOW")
            c = SEVERITY_COLORS.get(worst, "#888")
            types = html_lib.escape(", ".join(sorted({f.threat_type for f in ip_f})))
            bar_w = min(score, 300) / 300 * 100
            ip_rows += (
                f"<tr>"
                f"<td class='rnk'>#{rank}</td>"
                f"<td class='ip'>{html_lib.escape(ip)}</td>"
                f"<td>{ip_hits[ip]}</td>"
                f"<td><span class='badge' style='background:{c}'>{worst}</span></td>"
                f"<td style='font-size:.75rem;color:#8b949e'>{types}</td>"
                f"<td><div class='sbar'>"
                f"<div class='sbar-fill' style='width:{bar_w:.0f}%;max-width:80px;background:{c}'></div>"
                f"<span class='sbar-val'>{score}</span></div></td>"
                "</tr>"
            )

        findings_table = (
            f"<table id='ft'><thead><tr>"
            "<th>Timestamp</th><th>Source IP</th><th>Threat Type</th>"
            "<th>Severity</th><th>Description</th><th>Evidence</th>"
            f"</tr></thead><tbody>{finding_rows}</tbody></table>"
            if findings else "<div class='empty'>&#x2705; No threats detected</div>"
        )
        ip_table = (
            "<table><thead><tr>"
            "<th>#</th><th>IP Address</th><th>Findings</th>"
            "<th>Max Severity</th><th>Threat Types</th><th>Risk Score</th>"
            f"</tr></thead><tbody>{ip_rows}</tbody></table>"
            if top_ips else "<div class='empty'>No suspicious IPs identified</div>"
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Log Analysis Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
{_HTML_STYLE}
.risk-banner {{ background: linear-gradient(90deg, {risk_color}1a, transparent); border-left: 4px solid {risk_color}; }}
</style>
</head>
<body>

<header class="hdr">
  <div class="hdr-left">
    <div class="hdr-icon">&#x1F6E1;</div>
    <div>
      <h1>Security Log Analysis Report</h1>
      <div class="hdr-sub">Automated Threat Detection &amp; Intelligence Platform</div>
    </div>
  </div>
  <div class="hdr-meta">
    <div><strong>Analyst:</strong> Chukwuebuka Okonkwo</div>
    <div style="color:#8b949e;font-size:.72rem;">Security Analyst &nbsp;|&nbsp; CompTIA Security+ &nbsp;|&nbsp; ISC2 CC</div>
    <div><a href="https://github.com/osnoko" target="_blank" rel="noopener" style="color:#79c0ff;text-decoration:none;">&#x1F517; github.com/osnoko</a></div>
    <div style="margin-top:4px;padding-top:4px;border-top:1px solid #21262d;"><strong>Source:</strong> {html_lib.escape(log_file)}</div>
    <div><strong>Generated:</strong> {html_lib.escape(generated)}</div>
    <div><strong>Log Entries Parsed:</strong> {n_entries:,}</div>
  </div>
</header>

<div class="risk-banner">
  <span class="risk-badge" style="background:{risk_color}">{risk}</span>
  <span>Overall Risk Level &mdash; <strong>{n_total}</strong> threat indicator(s) across <strong>{n_entries:,}</strong> log entries</span>
</div>

<div class="wrap">

  <!-- ── Metric Cards ── -->
  <div class="metrics">
    <div class="card" style="--ac:#e6edf3"><div class="card-lbl">Total Findings</div><div class="card-val" style="color:#e6edf3">{n_total}</div><div class="card-desc">Security events detected</div></div>
    <div class="card" style="--ac:#a855f7"><div class="card-lbl">Critical</div><div class="card-val">{n_critical}</div><div class="card-desc">Immediate response required</div></div>
    <div class="card" style="--ac:#ef4444"><div class="card-lbl">High</div><div class="card-val">{n_high}</div><div class="card-desc">Investigate promptly</div></div>
    <div class="card" style="--ac:#f59e0b"><div class="card-lbl">Medium</div><div class="card-val">{n_medium}</div><div class="card-desc">Monitor and review</div></div>
    <div class="card" style="--ac:#3b82f6"><div class="card-lbl">Low</div><div class="card-val">{n_low}</div><div class="card-desc">Informational</div></div>
    <div class="card" style="--ac:#22c55e"><div class="card-lbl">Log Entries</div><div class="card-val" style="color:#22c55e">{n_entries:,}</div><div class="card-desc">Total events parsed</div></div>
  </div>

  <!-- ── Charts ── -->
  <div class="charts">
    <div class="chart-box span-full">
      <div class="chart-lbl">&#x1F4C8; Event &amp; Threat Timeline</div>
      <div class="ch" style="height:180px"><canvas id="cTL"></canvas></div>
    </div>
    <div class="chart-box">
      <div class="chart-lbl">&#x26A0;&#xFE0F; Severity Distribution</div>
      <div class="ch"><canvas id="cSEV"></canvas></div>
    </div>
    <div class="chart-box" style="grid-column:span 2">
      <div class="chart-lbl">&#x1F4CB; Threat Categories</div>
      <div class="ch"><canvas id="cTH"></canvas></div>
    </div>
  </div>

  <!-- ── Top IPs ── -->
  <div class="tbl-card">
    <div class="tbl-hdr">
      <span class="tbl-title">&#x1F3AF; Top Suspicious IP Addresses</span>
      <span class="tbl-count">{len(top_ips)} IPs</span>
    </div>
    <div class="tbl-scroll">{ip_table}</div>
  </div>

  <!-- ── Detailed Findings ── -->
  <div class="tbl-card">
    <div class="tbl-hdr">
      <span class="tbl-title">&#x1F50D; Detailed Threat Findings</span>
      <span class="tbl-count">{n_total} findings</span>
    </div>
    <div class="filters">
      <span class="f-lbl">Filter:</span>
      <button class="fbtn on-all"      onclick="filt('all',this)">All ({n_total})</button>
      <button class="fbtn"             onclick="filt('CRITICAL',this)">Critical ({n_critical})</button>
      <button class="fbtn"             onclick="filt('HIGH',this)">High ({n_high})</button>
      <button class="fbtn"             onclick="filt('MEDIUM',this)">Medium ({n_medium})</button>
      <button class="fbtn"             onclick="filt('LOW',this)">Low ({n_low})</button>
    </div>
    <div class="tbl-scroll">{findings_table}</div>
  </div>

</div>

<footer>
  Built by <strong style="color:#c9d1e0;">Chukwuebuka Okonkwo</strong> using Claude Code
  &nbsp;&bull;&nbsp;
  <a href="https://github.com/osnoko" target="_blank" rel="noopener" style="color:#79c0ff;text-decoration:none;">github.com/osnoko</a>
  &nbsp;&bull;&nbsp;
  Hamilton, Ontario, Canada
  <br>
  <span style="color:#30363d;">Security Log Analyzer &bull; Generated {html_lib.escape(generated)} &bull; For authorized security analysis only</span>
</footer>

<script>
Chart.defaults.color = '#7d8590';
Chart.defaults.borderColor = '#21262d';

// Timeline
new Chart(document.getElementById('cTL'), {{
  type: 'bar',
  data: {{
    labels: {tl_json},
    datasets: [
      {{ label:'All Events', data:{te_json}, backgroundColor:'#1f6feb33', borderColor:'#1f6feb', borderWidth:1, order:2 }},
      {{ label:'Threats',    data:{tt_json}, type:'line', tension:0.35,
         backgroundColor:'#ef444433', borderColor:'#ef4444', borderWidth:2,
         pointRadius:3, pointHoverRadius:5, fill:true, order:1 }}
    ]
  }},
  options: {{
    responsive:true, maintainAspectRatio:false,
    interaction:{{ mode:'index', intersect:false }},
    plugins:{{ legend:{{ labels:{{ boxWidth:11, font:{{ size:11 }} }} }} }},
    scales:{{
      x:{{ grid:{{ color:'#21262d' }}, ticks:{{ font:{{ size:9 }}, maxTicksLimit:24 }} }},
      y:{{ grid:{{ color:'#21262d' }}, beginAtZero:true, ticks:{{ precision:0 }} }}
    }}
  }}
}});

// Severity doughnut
new Chart(document.getElementById('cSEV'), {{
  type: 'doughnut',
  data: {{
    labels: ['Critical','High','Medium','Low'],
    datasets: [{{
      data: {sev_data},
      backgroundColor: ['#a855f7','#ef4444','#f59e0b','#3b82f6'],
      borderColor: '#161b27', borderWidth: 3, hoverOffset: 8
    }}]
  }},
  options: {{
    responsive:true, maintainAspectRatio:false, cutout:'62%',
    plugins:{{ legend:{{ position:'right', labels:{{ boxWidth:11, padding:10, font:{{ size:11 }} }} }} }}
  }}
}});

// Threat categories
new Chart(document.getElementById('cTH'), {{
  type: 'bar',
  data: {{
    labels: {th_labels},
    datasets: [{{
      label: 'Count', data: {th_data},
      backgroundColor: ['#a855f7aa','#ef4444aa','#f59e0baa','#3b82f6aa','#22c55eaa','#06b6d4aa','#ec4899aa','#84cc16aa'],
      borderColor:     ['#a855f7',  '#ef4444',  '#f59e0b',  '#3b82f6',  '#22c55e',  '#06b6d4',  '#ec4899',  '#84cc16'],
      borderWidth: 1, borderRadius: 4
    }}]
  }},
  options: {{
    indexAxis:'y', responsive:true, maintainAspectRatio:false,
    plugins:{{ legend:{{ display:false }} }},
    scales:{{
      x:{{ grid:{{ color:'#21262d' }}, beginAtZero:true, ticks:{{ precision:0 }} }},
      y:{{ grid:{{ color:'#21262d' }}, ticks:{{ font:{{ size:10 }} }} }}
    }}
  }}
}});

// Filter table
function filt(sev, btn) {{
  document.querySelectorAll('.fbtn').forEach(b => {{
    b.className = 'fbtn';
  }});
  const cls = sev === 'all' ? 'on-all'
    : sev === 'CRITICAL' ? 'on-critical'
    : sev === 'HIGH'     ? 'on-high'
    : sev === 'MEDIUM'   ? 'on-medium'
    : 'on-low';
  btn.classList.add(cls);
  document.querySelectorAll('#ft tbody tr').forEach(r => {{
    r.style.display = (sev === 'all' || r.dataset.sev === sev) ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""


# ─── Sample Log Generator ─────────────────────────────────────────────────────

def generate_sample_logs(path: str = "sample_logs.txt"):
    """Write a realistic multi-format log file that demonstrates all detections."""
    content = """\
# =============================================================================
# Security Log Analyzer — Sample Log File
# Demonstrates detection across Windows Event Logs, Linux auth.log,
# and Apache access logs. Contains realistic attack scenarios.
# =============================================================================

# ─── Linux auth.log / SSH entries ─────────────────────────────────────────────

# [NORMAL] Legitimate business-hours logins
Apr  1 08:12:04 prod-web-01 sshd[4421]: Accepted password for alice from 10.10.1.20 port 51023 ssh2
Apr  1 08:22:15 prod-web-01 sshd[4455]: Accepted password for bob from 10.10.1.21 port 52011 ssh2
Apr  1 09:00:44 prod-web-01 sshd[4501]: Accepted password for devops from 10.10.1.5 port 49882 ssh2
Apr  1 10:15:03 prod-web-01 sshd[4680]: Accepted publickey for deploy from 10.10.1.8 port 60211 ssh2
Apr  1 14:35:11 prod-web-01 sshd[5102]: Accepted password for alice from 10.10.1.20 port 53201 ssh2
Apr  1 16:47:33 prod-web-01 sshd[5444]: Accepted password for devops from 10.10.1.5 port 55123 ssh2

# [SCENARIO 1 — CRITICAL] Brute force attack from 45.33.32.156 — then root compromise
Apr  1 23:42:01 prod-web-01 sshd[7001]: Failed password for root from 45.33.32.156 port 43211 ssh2
Apr  1 23:42:03 prod-web-01 sshd[7002]: Failed password for root from 45.33.32.156 port 43212 ssh2
Apr  1 23:42:05 prod-web-01 sshd[7003]: Failed password for root from 45.33.32.156 port 43213 ssh2
Apr  1 23:42:07 prod-web-01 sshd[7004]: Failed password for invalid user admin from 45.33.32.156 port 43214 ssh2
Apr  1 23:42:09 prod-web-01 sshd[7005]: Failed password for invalid user administrator from 45.33.32.156 port 43215 ssh2
Apr  1 23:42:11 prod-web-01 sshd[7006]: Failed password for root from 45.33.32.156 port 43216 ssh2
Apr  1 23:42:13 prod-web-01 sshd[7007]: Failed password for root from 45.33.32.156 port 43217 ssh2
Apr  1 23:42:15 prod-web-01 sshd[7008]: Failed password for root from 45.33.32.156 port 43218 ssh2
Apr  1 23:42:17 prod-web-01 sshd[7009]: Failed password for root from 45.33.32.156 port 43219 ssh2
Apr  1 23:42:20 prod-web-01 sshd[7010]: Accepted password for root from 45.33.32.156 port 43220 ssh2

# [SCENARIO 2 — HIGH] Brute force (no success) from 203.0.113.88
Apr  2 08:11:01 prod-web-01 sshd[9001]: Failed password for invalid user oracle from 203.0.113.88 port 11001 ssh2
Apr  2 08:11:03 prod-web-01 sshd[9002]: Failed password for invalid user postgres from 203.0.113.88 port 11002 ssh2
Apr  2 08:11:05 prod-web-01 sshd[9003]: Failed password for invalid user mysql from 203.0.113.88 port 11003 ssh2
Apr  2 08:11:07 prod-web-01 sshd[9004]: Failed password for invalid user ubuntu from 203.0.113.88 port 11004 ssh2
Apr  2 08:11:09 prod-web-01 sshd[9005]: Failed password for invalid user deploy from 203.0.113.88 port 11005 ssh2
Apr  2 08:11:11 prod-web-01 sshd[9006]: Failed password for invalid user git from 203.0.113.88 port 11006 ssh2
Apr  2 08:11:13 prod-web-01 sshd[9007]: Failed password for invalid user ansible from 203.0.113.88 port 11007 ssh2

# [SCENARIO 3 — MEDIUM] Off-hours successful logins from suspicious external IP
Apr  2 01:15:33 prod-web-01 sshd[8001]: Accepted password for alice from 198.51.100.77 port 54400 ssh2
Apr  2 03:44:22 prod-db-01 sshd[8212]: Accepted password for dbadmin from 198.51.100.77 port 58800 ssh2

# [SCENARIO 4 — HIGH] Privilege escalation — www-data not in sudoers
Apr  1 11:22:01 prod-web-01 sudo: www-data : user NOT in sudoers ; TTY=pts/2 ; PWD=/var/www/html ; USER=root ; COMMAND=/bin/bash
Apr  1 11:22:15 prod-web-01 sudo: www-data : user NOT in sudoers ; TTY=pts/2 ; PWD=/var/www/html ; USER=root ; COMMAND=/usr/bin/id
Apr  1 14:05:44 prod-web-01 sudo:    apache : 3 incorrect password attempts ; TTY=pts/3 ; PWD=/etc ; USER=root ; COMMAND=/bin/cat /etc/shadow

# ─── Apache Access Log entries ────────────────────────────────────────────────

# [NORMAL] Regular web traffic
192.168.1.100 - - [01/Apr/2026:08:30:12 +0000] "GET /index.html HTTP/1.1" 200 5120 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/123"
192.168.1.100 - - [01/Apr/2026:08:30:15 +0000] "GET /about.html HTTP/1.1" 200 3200 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/123"
10.10.1.50 - - [01/Apr/2026:09:45:22 +0000] "POST /api/login HTTP/1.1" 200 450 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
10.10.1.51 - - [01/Apr/2026:10:15:33 +0000] "GET /dashboard HTTP/1.1" 200 8900 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
10.10.1.52 - - [01/Apr/2026:11:00:01 +0000] "GET /products HTTP/1.1" 200 12400 "-" "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)"
10.10.1.53 - - [01/Apr/2026:14:22:44 +0000] "GET /contact HTTP/1.1" 200 2900 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

# [SCENARIO 5 — CRITICAL] SQLMap automated SQL injection scanning
185.220.101.34 - - [01/Apr/2026:13:22:01 +0000] "GET /search?q=1'+OR+'1'%3D'1 HTTP/1.1" 500 287 "-" "sqlmap/1.7.8#stable (https://sqlmap.org)"
185.220.101.34 - - [01/Apr/2026:13:22:02 +0000] "GET /login?user=admin'+--+- HTTP/1.1" 200 1243 "-" "sqlmap/1.7.8#stable (https://sqlmap.org)"
185.220.101.34 - - [01/Apr/2026:13:22:03 +0000] "GET /products?id=1+UNION+SELECT+null,table_name,null+FROM+information_schema.tables-- HTTP/1.1" 500 287 "-" "sqlmap/1.7.8#stable (https://sqlmap.org)"
185.220.101.34 - - [01/Apr/2026:13:22:04 +0000] "GET /api/users?id=1;DROP+TABLE+users-- HTTP/1.1" 500 287 "-" "sqlmap/1.7.8#stable (https://sqlmap.org)"
185.220.101.34 - - [01/Apr/2026:13:22:05 +0000] "GET /page?id=1+AND+SLEEP(5)-- HTTP/1.1" 200 5120 "-" "sqlmap/1.7.8#stable (https://sqlmap.org)"
185.220.101.34 - - [01/Apr/2026:13:22:06 +0000] "GET /items?id=1+AND+1=1 HTTP/1.1" 200 5120 "-" "sqlmap/1.7.8#stable (https://sqlmap.org)"
185.220.101.34 - - [01/Apr/2026:13:22:07 +0000] "GET /view?id=1+UNION+SELECT+username,password,3+FROM+users-- HTTP/1.1" 500 287 "-" "sqlmap/1.7.8#stable (https://sqlmap.org)"

# [SCENARIO 6 — MEDIUM] Nikto web vulnerability scan
172.16.254.1 - - [01/Apr/2026:14:45:11 +0000] "GET /cgi-bin/test.cgi HTTP/1.1" 404 209 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:001425)"
172.16.254.1 - - [01/Apr/2026:14:45:12 +0000] "GET /.git/config HTTP/1.1" 404 209 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:001426)"
172.16.254.1 - - [01/Apr/2026:14:45:13 +0000] "GET /phpinfo.php HTTP/1.1" 404 209 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:001427)"
172.16.254.1 - - [01/Apr/2026:14:45:14 +0000] "GET /wp-login.php HTTP/1.1" 404 209 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:001428)"
172.16.254.1 - - [01/Apr/2026:14:45:15 +0000] "GET /admin/config.php HTTP/1.1" 404 209 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:001429)"
172.16.254.1 - - [01/Apr/2026:14:45:16 +0000] "GET /server-status HTTP/1.1" 403 287 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:001430)"
172.16.254.1 - - [01/Apr/2026:14:45:17 +0000] "GET /.env HTTP/1.1" 404 209 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:001431)"

# [SCENARIO 7 — HIGH] Path traversal + admin probing from 91.108.56.22
91.108.56.22 - - [01/Apr/2026:15:30:01 +0000] "GET /download?file=../../../etc/passwd HTTP/1.1" 400 187 "-" "python-requests/2.31.0"
91.108.56.22 - - [01/Apr/2026:15:30:02 +0000] "GET /view?path=../../../../windows/system32/config/sam HTTP/1.1" 400 187 "-" "python-requests/2.31.0"
91.108.56.22 - - [01/Apr/2026:15:30:03 +0000] "GET /static/../../../etc/shadow HTTP/1.1" 400 187 "-" "python-requests/2.31.0"
91.108.56.22 - - [01/Apr/2026:15:30:04 +0000] "GET /images/../admin/config.php HTTP/1.1" 403 209 "-" "python-requests/2.31.0"
91.108.56.22 - - [01/Apr/2026:15:30:10 +0000] "GET /admin HTTP/1.1" 403 209 "-" "python-requests/2.31.0"
91.108.56.22 - - [01/Apr/2026:15:30:11 +0000] "GET /phpmyadmin HTTP/1.1" 404 209 "-" "python-requests/2.31.0"
91.108.56.22 - - [01/Apr/2026:15:30:12 +0000] "GET /wp-admin HTTP/1.1" 404 209 "-" "python-requests/2.31.0"
91.108.56.22 - - [01/Apr/2026:15:30:13 +0000] "GET /administrator HTTP/1.1" 404 209 "-" "python-requests/2.31.0"
91.108.56.22 - - [01/Apr/2026:15:30:14 +0000] "GET /manager/html HTTP/1.1" 404 209 "-" "python-requests/2.31.0"
91.108.56.22 - - [01/Apr/2026:15:30:15 +0000] "GET /cpanel HTTP/1.1" 404 209 "-" "python-requests/2.31.0"

# ─── Windows Security Event Log entries ──────────────────────────────────────

# [NORMAL] Legitimate Windows logins
2026-04-01 08:05:11 | EventID: 4624 | Account: jsmith | Source IP: 10.10.1.30 | Dest Port: 445 | Computer: DC01 | Result: Audit Success
2026-04-01 08:22:33 | EventID: 4624 | Account: mjones | Source IP: 10.10.1.31 | Dest Port: 445 | Computer: DC01 | Result: Audit Success
2026-04-01 09:00:00 | EventID: 4624 | Account: svcBackup | Source IP: 10.10.1.10 | Dest Port: 445 | Computer: FS01 | Result: Audit Success
2026-04-01 09:14:22 | EventID: 4624 | Account: hrodriguez | Source IP: 10.10.1.44 | Dest Port: 3389 | Computer: WS-HR01 | Result: Audit Success

# [SCENARIO 8 — HIGH] Windows brute force from 198.51.100.200 via SMB
2026-04-01 17:33:01 | EventID: 4625 | Account: administrator | Source IP: 198.51.100.200 | Dest Port: 445 | Computer: DC01 | Result: Audit Failure
2026-04-01 17:33:03 | EventID: 4625 | Account: admin | Source IP: 198.51.100.200 | Dest Port: 445 | Computer: DC01 | Result: Audit Failure
2026-04-01 17:33:05 | EventID: 4625 | Account: Administrator | Source IP: 198.51.100.200 | Dest Port: 445 | Computer: DC01 | Result: Audit Failure
2026-04-01 17:33:07 | EventID: 4625 | Account: sysadmin | Source IP: 198.51.100.200 | Dest Port: 445 | Computer: DC01 | Result: Audit Failure
2026-04-01 17:33:09 | EventID: 4625 | Account: root | Source IP: 198.51.100.200 | Dest Port: 445 | Computer: DC01 | Result: Audit Failure
2026-04-01 17:33:11 | EventID: 4625 | Account: superuser | Source IP: 198.51.100.200 | Dest Port: 445 | Computer: DC01 | Result: Audit Failure
2026-04-01 17:33:13 | EventID: 4625 | Account: backup | Source IP: 198.51.100.200 | Dest Port: 445 | Computer: DC01 | Result: Audit Failure

# [SCENARIO 9 — MEDIUM] Suspicious privilege assignment to temp account
2026-04-01 17:45:22 | EventID: 4672 | Account: tempuser | Source IP: 10.10.1.45 | Dest Port: 445 | Computer: DC01 | Result: Audit Success
2026-04-01 17:45:23 | EventID: 4673 | Account: tempuser | Source IP: 10.10.1.45 | Dest Port: 445 | Computer: DC01 | Result: Audit Success

# [SCENARIO 10 — HIGH] Port scan from 104.21.45.67 (Windows Firewall EventID 5156)
2026-04-01 19:00:01 | EventID: 5156 | Account: SYSTEM | Source IP: 104.21.45.67 | Dest Port: 21 | Computer: EDGE01 | Result: Permitted
2026-04-01 19:00:02 | EventID: 5156 | Account: SYSTEM | Source IP: 104.21.45.67 | Dest Port: 22 | Computer: EDGE01 | Result: Permitted
2026-04-01 19:00:02 | EventID: 5156 | Account: SYSTEM | Source IP: 104.21.45.67 | Dest Port: 23 | Computer: EDGE01 | Result: Permitted
2026-04-01 19:00:03 | EventID: 5156 | Account: SYSTEM | Source IP: 104.21.45.67 | Dest Port: 25 | Computer: EDGE01 | Result: Permitted
2026-04-01 19:00:03 | EventID: 5156 | Account: SYSTEM | Source IP: 104.21.45.67 | Dest Port: 80 | Computer: EDGE01 | Result: Permitted
2026-04-01 19:00:04 | EventID: 5156 | Account: SYSTEM | Source IP: 104.21.45.67 | Dest Port: 443 | Computer: EDGE01 | Result: Permitted
2026-04-01 19:00:04 | EventID: 5156 | Account: SYSTEM | Source IP: 104.21.45.67 | Dest Port: 3306 | Computer: EDGE01 | Result: Permitted
2026-04-01 19:00:05 | EventID: 5156 | Account: SYSTEM | Source IP: 104.21.45.67 | Dest Port: 3389 | Computer: EDGE01 | Result: Permitted
2026-04-01 19:00:05 | EventID: 5156 | Account: SYSTEM | Source IP: 104.21.45.67 | Dest Port: 5432 | Computer: EDGE01 | Result: Permitted
2026-04-01 19:00:06 | EventID: 5156 | Account: SYSTEM | Source IP: 104.21.45.67 | Dest Port: 6379 | Computer: EDGE01 | Result: Permitted
2026-04-01 19:00:06 | EventID: 5156 | Account: SYSTEM | Source IP: 104.21.45.67 | Dest Port: 8080 | Computer: EDGE01 | Result: Permitted
2026-04-01 19:00:07 | EventID: 5156 | Account: SYSTEM | Source IP: 104.21.45.67 | Dest Port: 8443 | Computer: EDGE01 | Result: Permitted
2026-04-01 19:00:07 | EventID: 5156 | Account: SYSTEM | Source IP: 104.21.45.67 | Dest Port: 27017 | Computer: EDGE01 | Result: Permitted

# [SCENARIO 11 — MEDIUM] Off-hours Windows RDP login from external IP
2026-04-02 02:30:15 | EventID: 4624 | Account: helpdesk | Source IP: 185.220.101.100 | Dest Port: 3389 | Computer: ADMIN01 | Result: Audit Success

# [NORMAL] End of day logoff events
2026-04-01 17:58:44 | EventID: 4634 | Account: jsmith | Source IP: 10.10.1.30 | Dest Port: 445 | Computer: DC01 | Result: Audit Success
2026-04-01 18:02:12 | EventID: 4634 | Account: mjones | Source IP: 10.10.1.31 | Dest Port: 445 | Computer: DC01 | Result: Audit Success
2026-04-01 18:15:09 | EventID: 4634 | Account: hrodriguez | Source IP: 10.10.1.44 | Dest Port: 3389 | Computer: WS-HR01 | Result: Audit Success
"""
    Path(path).write_text(content, encoding="utf-8")
    print(f"[+] Sample log written: {path}")


# ─── CLI Entry Point ──────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="Security Log Analyzer - detects threats across multiple log formats",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
log formats supported:
  Linux auth.log   - syslog-style SSH/sudo entries
  Apache/Nginx     - Combined Log Format access logs
  Windows Sec. Log - pipe-delimited single-line export
                     (EventID|Account|Source IP|Dest Port|Computer|Result)

examples:
  python log_analyzer.py sample_logs.txt
  python log_analyzer.py /var/log/auth.log -o auth_report.html
  python log_analyzer.py --generate-samples
""",
    )
    ap.add_argument("log_file", nargs="?", help="Log file to analyze")
    ap.add_argument("-o", "--output", default="report.html",
                    help="Output HTML report path (default: report.html)")
    ap.add_argument("--generate-samples", action="store_true",
                    help="Generate sample_logs.txt and analyze it")
    args = ap.parse_args()

    if args.generate_samples or args.log_file is None:
        generate_sample_logs("sample_logs.txt")
        args.log_file = "sample_logs.txt"

    log_path = Path(args.log_file)
    if not log_path.exists():
        print(f"[!] File not found: {log_path}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Parsing: {log_path}")
    parser = LogParser()
    entries, skipped = [], 0
    with open(log_path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            e = parser.parse_line(line)
            if e:
                entries.append(e)
            else:
                skipped += 1

    fmt_counts = Counter(e.log_format for e in entries)
    print(f"[*] Parsed {len(entries):,} entries  "
          f"(auth:{fmt_counts.get('auth',0)}  "
          f"apache:{fmt_counts.get('apache',0)}  "
          f"windows:{fmt_counts.get('windows',0)})  "
          f"- {skipped} lines skipped")

    if not entries:
        print("[!] No parseable entries found. Verify log format.", file=sys.stderr)
        sys.exit(1)

    print("[*] Running threat detection ...")
    findings = ThreatDetector().analyze(entries)

    sev = Counter(f.severity for f in findings)
    print()
    print("  Findings summary")
    print("  " + "-" * 40)
    print(f"  CRITICAL : {sev.get('CRITICAL', 0):>4}")
    print(f"  HIGH     : {sev.get('HIGH',     0):>4}")
    print(f"  MEDIUM   : {sev.get('MEDIUM',   0):>4}")
    print(f"  LOW      : {sev.get('LOW',      0):>4}")
    print("  " + "-" * 40)
    print(f"  TOTAL    : {len(findings):>4}")
    print()

    if findings:
        print("  Top findings:")
        for f in findings[:6]:
            desc = f.description[:65] + ("..." if len(f.description) > 65 else "")
            print(f"  [{f.severity:<8}] {f.source_ip:<18} {f.threat_type} - {desc}")
        print()

    print("[*] Generating HTML report ...")
    out = ReportGenerator().generate(findings, entries, str(log_path), args.output)
    print(f"[+] Report saved: {out}")
    print(f"[+] Open {out} in a browser to view the full analysis.")


if __name__ == "__main__":
    main()
