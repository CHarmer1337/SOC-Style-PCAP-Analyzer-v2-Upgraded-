#!/usr/bin/env python3
"""
SOC PCAP Analyzer
-----------------
A Python-based PCAP analysis tool simulating real SOC analyst workflows.

Detections:
  - Beaconing via Coefficient of Variation (CV) on inter-packet intervals  → T1071
  - DNS exfiltration via Shannon entropy + subdomain length scoring         → T1048.003
  - HTTP anomalies via keyword pattern matching                             → T1190
  - Rare / offensive port usage                                             → T1571
  - Composite risk score (0–100) with weighted multi-signal engine

Outputs: color-coded console, CSV, JSON

Author : Michael "Tony" Lee
License: MIT
"""

import argparse
import csv
import json
import math
import os
import random
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone

# ── Optional dependencies ──────────────────────────────────────────────────────
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

try:
    import pyshark
    HAS_PYSHARK = True
except ImportError:
    HAS_PYSHARK = False

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False


# ── Color helpers ──────────────────────────────────────────────────────────────
def _c(color, text):
    if HAS_COLOR:
        return f"{color}{text}{Style.RESET_ALL}"
    return text

RED    = lambda t: _c(Fore.RED,     t)
YELLOW = lambda t: _c(Fore.YELLOW,  t)
CYAN   = lambda t: _c(Fore.CYAN,    t)
GREEN  = lambda t: _c(Fore.GREEN,   t)
WHITE  = lambda t: _c(Fore.WHITE,   t)
BOLD   = lambda t: _c(Style.BRIGHT, t)


# ── Constants ──────────────────────────────────────────────────────────────────
KNOWN_C2_PORTS = {
    4444, 4445, 1337, 31337, 8888, 6666, 6667, 6668, 6669,
    9001, 9030, 1080, 3128, 8080, 8443, 4899, 5900, 5901,
}

KNOWN_BENIGN_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "cloudflare.com",
    "amazonaws.com", "akamai.com", "fastly.com", "windows.com",
    "windowsupdate.com", "office.com", "live.com", "outlook.com",
}

HTTP_OFFENSIVE_PATTERNS = [
    r"(?i)(cmd\.exe|powershell|/bin/sh|/bin/bash)",
    r"(?i)(wget|curl)\s+http",
    r"(?i)(base64|b64decode|frombase64string)",
    r"(?i)(mimikatz|cobalt.?strike|metasploit|empire|covenant)",
    r"(?i)(\.php\?.*=http|eval\(|passthru\(|system\()",
    r"(?i)(user-agent:\s*(python|go-http|curl|wget|libwww))",
    r"(?i)/etc/(passwd|shadow|hosts)",
    r"(?i)(union.*select|select.*from|drop\s+table)",
]

BEACON_THRESHOLDS = {
    "high":   (0.00, 0.10),   # CV range → score 100 (highly regular)
    "medium": (0.10, 0.25),   # CV range → score 80  (slightly jittered)
    "low":    (0.25, 0.60),   # CV range → score 40  (possible beacon)
    # > 0.60 → score 0 (irregular / benign)
}

RISK_BANDS = [
    (80, "CRITICAL", RED),
    (60, "HIGH",     RED),
    (40, "MEDIUM",   YELLOW),
    (20, "LOW",      GREEN),
    (0,  "INFO",     WHITE),
]


# ── Utility ────────────────────────────────────────────────────────────────────
def shannon_entropy(s: str) -> float:
    """Return Shannon entropy (bits) of string s."""
    if not s:
        return 0.0
    freq = defaultdict(int)
    for ch in s:
        freq[ch] += 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def risk_label(score: int):
    for threshold, label, color_fn in RISK_BANDS:
        if score >= threshold:
            return label, color_fn
    return "INFO", WHITE


def mean(lst):
    return sum(lst) / len(lst) if lst else 0.0


def stdev(lst):
    if len(lst) < 2:
        return 0.0
    m = mean(lst)
    variance = sum((x - m) ** 2 for x in lst) / (len(lst) - 1)
    return math.sqrt(variance)


def cv(lst):
    """Coefficient of Variation = stdev / mean"""
    m = mean(lst)
    return stdev(lst) / m if m else 0.0


# ── Risk Engine ────────────────────────────────────────────────────────────────
class RiskEngine:
    """Weighted composite risk scoring (0–100)."""

    WEIGHTS = {
        "connection_volume": 0.10,
        "beacon":            0.35,
        "dns_entropy":       0.25,
        "rare_port":         0.20,
        "http_anomaly":      0.10,
    }

    @staticmethod
    def score_connection_volume(count: int) -> int:
        if count >= 500: return 100
        if count >= 200: return 80
        if count >= 100: return 60
        if count >= 50:  return 40
        return 10

    @staticmethod
    def score_beacon_regularity(interval_cv: float) -> int:
        lo, hi = BEACON_THRESHOLDS["high"]
        if lo <= interval_cv < hi:   return 100
        lo, hi = BEACON_THRESHOLDS["medium"]
        if lo <= interval_cv < hi:   return 80
        lo, hi = BEACON_THRESHOLDS["low"]
        if lo <= interval_cv < hi:   return 40
        return 0

    @staticmethod
    def score_dns_entropy(entropy_bits: float, label_len: int) -> int:
        score = 0
        # High entropy subdomain → likely exfil
        if entropy_bits > 3.8:   score += 60
        elif entropy_bits > 3.0: score += 40
        elif entropy_bits > 2.5: score += 20
        # Long subdomain label → more data per query
        if label_len > 50:   score += 40
        elif label_len > 30: score += 20
        elif label_len > 20: score += 10
        return min(score, 100)

    @staticmethod
    def score_rare_port(port: int) -> int:
        return 100 if port in KNOWN_C2_PORTS else 0

    @staticmethod
    def score_http_anomaly(count: int) -> int:
        if count >= 3: return 100
        if count == 2: return 70
        if count == 1: return 40
        return 0

    @classmethod
    def composite(cls, components: dict) -> int:
        total = sum(
            cls.WEIGHTS.get(k, 0) * v
            for k, v in components.items()
        )
        return min(int(total), 100)


# ── Beacon Detector ────────────────────────────────────────────────────────────
class BeaconDetector:
    """
    Track per-IP packet timestamps.
    Compute inter-packet intervals → CV → beacon score.
    """

    def __init__(self, min_packets: int = 10):
        self.min_packets = min_packets
        self._timestamps: dict[str, list[float]] = defaultdict(list)

    def record(self, src_ip: str, timestamp: float):
        self._timestamps[src_ip].append(timestamp)

    def analyze(self) -> list[dict]:
        results = []
        for ip, times in self._timestamps.items():
            times_sorted = sorted(times)
            if len(times_sorted) < self.min_packets:
                continue
            intervals = [
                times_sorted[i + 1] - times_sorted[i]
                for i in range(len(times_sorted) - 1)
                if times_sorted[i + 1] - times_sorted[i] > 0
            ]
            if not intervals:
                continue
            interval_cv = cv(intervals)
            score = RiskEngine.score_beacon_regularity(interval_cv)
            results.append({
                "ip":           ip,
                "packet_count": len(times_sorted),
                "mean_interval": round(mean(intervals), 3),
                "interval_cv":  round(interval_cv, 4),
                "beacon_score": score,
            })
        return sorted(results, key=lambda r: r["beacon_score"], reverse=True)


# ── DNS Analyzer ───────────────────────────────────────────────────────────────
class DNSAnalyzer:
    """
    Score DNS queries for potential data exfiltration.
    Filters known-benign apex domains.
    """

    def __init__(self):
        self._queries: list[str] = []

    def record(self, qname: str):
        self._queries.append(qname.rstrip(".").lower())

    def _apex(self, fqdn: str) -> str:
        parts = fqdn.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else fqdn

    def analyze(self) -> dict:
        suspicious = []
        seen = set()

        for qname in self._queries:
            if qname in seen:
                continue
            seen.add(qname)

            apex = self._apex(qname)
            if apex in KNOWN_BENIGN_DOMAINS:
                continue

            parts = qname.split(".")
            # Score the leftmost subdomain label (most likely exfil payload)
            subdomain = parts[0] if len(parts) > 2 else qname
            ent = shannon_entropy(subdomain)
            label_len = len(subdomain)
            score = RiskEngine.score_dns_entropy(ent, label_len)

            if score >= 40:
                suspicious.append({
                    "qname":      qname,
                    "subdomain":  subdomain,
                    "entropy":    round(ent, 2),
                    "label_len":  label_len,
                    "dns_score":  score,
                })

        suspicious.sort(key=lambda r: r["dns_score"], reverse=True)
        return {
            "total_queries":   len(self._queries),
            "unique_domains":  len(seen),
            "suspicious":      suspicious,
        }


# ── Port Analyzer ──────────────────────────────────────────────────────────────
class PortAnalyzer:
    """Detect usage of rare/offensive destination ports → T1571."""

    def __init__(self):
        self._connections: list[tuple[str, int]] = []

    def record(self, src_ip: str, dst_port: int):
        self._connections.append((src_ip, dst_port))

    def analyze(self) -> list[dict]:
        hits: dict[tuple, int] = defaultdict(int)
        for src, port in self._connections:
            if port in KNOWN_C2_PORTS:
                hits[(src, port)] += 1
        return [
            {"src_ip": src, "dst_port": port, "count": count, "port_score": 100}
            for (src, port), count in sorted(hits.items(), key=lambda x: -x[1])
        ]


# ── HTTP Analyzer ──────────────────────────────────────────────────────────────
class HTTPAnalyzer:
    """Keyword pattern matching against known offensive HTTP indicators → T1190."""

    def __init__(self):
        self._payloads: list[tuple[str, str]] = []   # (src_ip, raw_str)
        self._compiled = [re.compile(p) for p in HTTP_OFFENSIVE_PATTERNS]

    def record(self, src_ip: str, raw: str):
        self._payloads.append((src_ip, raw))

    def analyze(self) -> list[dict]:
        results: dict[str, dict] = {}
        for src, raw in self._payloads:
            matches = [p.pattern for p in self._compiled if p.search(raw)]
            if matches:
                if src not in results:
                    results[src] = {"src_ip": src, "match_count": 0, "patterns": []}
                results[src]["match_count"] += len(matches)
                results[src]["patterns"].extend(matches)
        for r in results.values():
            r["patterns"] = list(set(r["patterns"]))
            r["http_score"] = RiskEngine.score_http_anomaly(r["match_count"])
        return sorted(results.values(), key=lambda r: r["http_score"], reverse=True)


# ── Top Talkers ────────────────────────────────────────────────────────────────
class TopTalkers:
    def __init__(self):
        self._counts: dict[str, int] = defaultdict(int)

    def record(self, src_ip: str):
        self._counts[src_ip] += 1

    def top(self, n: int = 10) -> list[tuple[str, int]]:
        return sorted(self._counts.items(), key=lambda x: -x[1])[:n]


# ── Orchestrator ───────────────────────────────────────────────────────────────
class PCAPAnalyzer:
    def __init__(self, threshold: int = 15):
        self.threshold   = threshold
        self.beacon_det  = BeaconDetector(min_packets=threshold)
        self.dns_an      = DNSAnalyzer()
        self.port_an     = PortAnalyzer()
        self.http_an     = HTTPAnalyzer()
        self.talkers     = TopTalkers()
        self.packet_count = 0
        self.start_ts     = None
        self.end_ts       = None
        self.pcap_file    = None

    # ── PCAP loading ──────────────────────────────────────────────────────────
    def load_pcap(self, path: str):
        if not HAS_PYSHARK:
            print(RED("ERROR: pyshark not installed. Run: pip install pyshark"))
            print(RED("       Wireshark/tshark also required: https://www.wireshark.org/download.html"))
            sys.exit(1)

        self.pcap_file = os.path.basename(path)
        cap = pyshark.FileCapture(path, keep_packets=False)

        for pkt in cap:
            try:
                ts = float(pkt.sniff_timestamp)
            except Exception:
                continue

            self.packet_count += 1
            if self.start_ts is None or ts < self.start_ts:
                self.start_ts = ts
            if self.end_ts is None or ts > self.end_ts:
                self.end_ts = ts

            src_ip = None
            dst_port = None

            # Network layer
            if hasattr(pkt, "ip"):
                src_ip = pkt.ip.src
            elif hasattr(pkt, "ipv6"):
                src_ip = pkt.ipv6.src

            if src_ip:
                self.talkers.record(src_ip)
                self.beacon_det.record(src_ip, ts)

            # Transport layer
            if hasattr(pkt, "tcp"):
                try:
                    dst_port = int(pkt.tcp.dstport)
                except Exception:
                    pass
            elif hasattr(pkt, "udp"):
                try:
                    dst_port = int(pkt.udp.dstport)
                except Exception:
                    pass

            if src_ip and dst_port:
                self.port_an.record(src_ip, dst_port)

            # DNS
            if hasattr(pkt, "dns") and hasattr(pkt.dns, "qry_name"):
                self.dns_an.record(pkt.dns.qry_name)

            # HTTP
            if hasattr(pkt, "http"):
                raw = str(pkt.http)
                if src_ip:
                    self.http_an.record(src_ip, raw)

        cap.close()

    # ── Demo mode (synthetic data) ─────────────────────────────────────────────
    def load_demo(self):
        self.pcap_file = "DEMO_MODE"
        self.packet_count = 3142
        base_ts = 1700000000.0
        self.start_ts = base_ts
        self.end_ts   = base_ts + 3600

        ips = {
            "192.168.1.105": {"count": 312, "cv": 0.183, "port": 443},
            "185.220.101.7":  {"count": 154, "cv": 0.047, "port": 4444},
            "10.0.0.44":      {"count": 187, "cv": 0.310, "port": 80},
            "172.16.5.22":    {"count": 89,  "cv": 0.720, "port": 8080},
            "10.0.0.1":       {"count": 211, "cv": 0.890, "port": 53},
        }

        rng = random.Random(42)
        for ip, props in ips.items():
            mean_interval = 30.0
            for i in range(props["count"]):
                jitter = rng.gauss(0, props["cv"] * mean_interval)
                ts = base_ts + i * mean_interval + jitter
                self.beacon_det.record(ip, ts)
                self.talkers.record(ip)
                self.port_an.record(ip, props["port"])

        # Suspicious DNS
        suspicious_names = [
            "a2fghj3kl9mn0pq.exfil-domain.xyz",
            "b3xyz8abc1def2ghi4jkl.tunnel.bad.io",
            "dGhpcyBpcyBhIHRlc3Q.evil-c2.ru",
            "update.microsoft.com",
            "api.github.com",
            "xn--4gbr3a1b2c3d4e5f6.net",
        ]
        for _ in range(487):
            self.dns_an.record(rng.choice(suspicious_names))

        # HTTP anomalies
        payloads = [
            ("192.168.1.105", "GET /shell.php?cmd=cmd.exe HTTP/1.1\r\nUser-Agent: python-requests/2.28"),
            ("185.220.101.7",  "POST /upload HTTP/1.1\r\n\r\npowershell -enc base64encodedpayload"),
            ("10.0.0.44",      "GET /index.html HTTP/1.1\r\nUser-Agent: Mozilla/5.0"),
        ]
        for ip, payload in payloads:
            self.http_an.record(ip, payload)

    # ── Full analysis ──────────────────────────────────────────────────────────
    def analyze(self) -> dict:
        beacon_results = self.beacon_det.analyze()
        dns_results    = self.dns_an.analyze()
        port_results   = self.port_an.analyze()
        http_results   = self.http_an.analyze()
        top_talkers    = self.talkers.top()

        # Build per-IP composite scores
        beacon_by_ip = {r["ip"]: r for r in beacon_results}
        http_by_ip   = {r["src_ip"]: r for r in http_results}
        port_by_ip   = defaultdict(int)
        for r in port_results:
            port_by_ip[r["src_ip"]] = max(port_by_ip[r["src_ip"]], r["port_score"])

        ip_scores = []
        for ip, count in top_talkers:
            components = {
                "connection_volume": RiskEngine.score_connection_volume(count),
                "beacon":            beacon_by_ip.get(ip, {}).get("beacon_score", 0),
                "dns_entropy":       0,
                "rare_port":         port_by_ip.get(ip, 0),
                "http_anomaly":      http_by_ip.get(ip, {}).get("http_score", 0),
            }
            score = RiskEngine.composite(components)
            ip_scores.append({
                "ip":         ip,
                "conn_count": count,
                "risk_score": score,
                "components": components,
            })

        duration = int((self.end_ts or 0) - (self.start_ts or 0))
        unique_ips = len(self.talkers._counts)

        return {
            "meta": {
                "file":       self.pcap_file,
                "analyzed":   datetime.now(timezone.utc).isoformat(),
                "packets":    self.packet_count,
                "duration_s": duration,
                "unique_ips": unique_ips,
            },
            "top_talkers":     ip_scores,
            "beaconing":       beacon_results,
            "dns":             dns_results,
            "rare_ports":      port_results,
            "http_anomalies":  http_results,
        }


# ── Reporter ───────────────────────────────────────────────────────────────────
class Reporter:
    SEP  = "─" * 60
    DSEP = "═" * 60

    def print_report(self, data: dict):
        m = data["meta"]
        print()
        print(BOLD(self.DSEP))
        print(BOLD("  SOC PCAP ANALYSIS REPORT"))
        print(f"  File     : {CYAN(m['file'])}")
        print(f"  Analyzed : {m['analyzed']}")
        print(f"  Packets  : {m['packets']:,}  |  Duration: {m['duration_s']}s")
        print(f"  Unique IPs: {m['unique_ips']}")
        print(BOLD(self.DSEP))

        # Top talkers
        print()
        print(BOLD("[TOP TALKERS]"))
        print(self.SEP)
        for t in data["top_talkers"][:10]:
            label, color_fn = risk_label(t["risk_score"])
            print(
                f"  {t['ip']:<20} {t['conn_count']:>5} conns"
                f"  Risk: {color_fn(f'{label:<8}')}"
                f"  Score: {color_fn(str(t['risk_score']))}"
            )

        # Beaconing
        print()
        print(BOLD("[BEACONING ALERTS — T1071]"))
        print(self.SEP)
        beacons = [b for b in data["beaconing"] if b["beacon_score"] >= 40]
        if beacons:
            for b in beacons:
                print(
                    f"  {RED('[!]')} {b['ip']:<20}"
                    f"  Pkts: {b['packet_count']:<6}"
                    f"  Interval CV: {b['interval_cv']:.3f}"
                    f"  Beacon Score: {RED(str(b['beacon_score']))}/100"
                )
        else:
            print(f"  {GREEN('No beaconing detected above threshold.')}")

        # DNS
        print()
        print(BOLD("[DNS ANALYSIS — T1048.003]"))
        print(self.SEP)
        dns = data["dns"]
        print(f"  Total queries: {dns['total_queries']}  |  Unique domains: {dns['unique_domains']}")
        susp = dns["suspicious"]
        if susp:
            print()
            print(f"  {YELLOW('Suspicious (high entropy):')}")
            for d in susp[:10]:
                print(
                    f"    {RED('[!]')} {d['qname']:<55}"
                    f"  Entropy: {RED(str(d['dns_score']))}/100"
                )
        else:
            print(f"  {GREEN('No suspicious DNS queries detected.')}")

        # Rare ports
        print()
        print(BOLD("[RARE PORT USAGE — T1571]"))
        print(self.SEP)
        ports = data["rare_ports"]
        if ports:
            for p in ports[:10]:
                print(
                    f"  {RED('[!]')} {p['src_ip']:<20}"
                    f"  → Port {RED(str(p['dst_port'])):<6}"
                    f"  ({p['count']} connections)"
                )
        else:
            print(f"  {GREEN('No suspicious port usage detected.')}")

        # HTTP
        print()
        print(BOLD("[HTTP ANOMALIES — T1190]"))
        print(self.SEP)
        http = data["http_anomalies"]
        if http:
            for h in http:
                print(
                    f"  {RED('[!]')} {h['src_ip']:<20}"
                    f"  Matches: {h['match_count']}"
                    f"  Score: {RED(str(h['http_score']))}/100"
                )
                for pat in h["patterns"][:3]:
                    print(f"       Pattern: {YELLOW(pat)}")
        else:
            print(f"  {GREEN('No HTTP anomalies detected.')}")

        print()
        print(BOLD(self.DSEP))
        print()

    # ── CSV ───────────────────────────────────────────────────────────────────
    def write_csv(self, data: dict, path: str):
        rows = []
        m = data["meta"]

        for t in data["top_talkers"]:
            rows.append({
                "category":   "TOP_TALKER",
                "ip":         t["ip"],
                "detail":     f"connections={t['conn_count']}",
                "risk_score": t["risk_score"],
                "ttp":        "",
                "file":       m["file"],
                "timestamp":  m["analyzed"],
            })

        for b in data["beaconing"]:
            if b["beacon_score"] >= 40:
                rows.append({
                    "category":   "BEACONING",
                    "ip":         b["ip"],
                    "detail":     f"cv={b['interval_cv']},pkts={b['packet_count']}",
                    "risk_score": b["beacon_score"],
                    "ttp":        "T1071",
                    "file":       m["file"],
                    "timestamp":  m["analyzed"],
                })

        for d in data["dns"]["suspicious"]:
            rows.append({
                "category":   "DNS_EXFIL",
                "ip":         "",
                "detail":     f"qname={d['qname']},entropy={d['entropy']}",
                "risk_score": d["dns_score"],
                "ttp":        "T1048.003",
                "file":       m["file"],
                "timestamp":  m["analyzed"],
            })

        for p in data["rare_ports"]:
            rows.append({
                "category":   "RARE_PORT",
                "ip":         p["src_ip"],
                "detail":     f"port={p['dst_port']},count={p['count']}",
                "risk_score": p["port_score"],
                "ttp":        "T1571",
                "file":       m["file"],
                "timestamp":  m["analyzed"],
            })

        for h in data["http_anomalies"]:
            rows.append({
                "category":   "HTTP_ANOMALY",
                "ip":         h["src_ip"],
                "detail":     f"matches={h['match_count']}",
                "risk_score": h["http_score"],
                "ttp":        "T1190",
                "file":       m["file"],
                "timestamp":  m["analyzed"],
            })

        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else [])
            writer.writeheader()
            writer.writerows(rows)
        print(GREEN(f"  [+] CSV report saved → {path}"))

    # ── JSON ──────────────────────────────────────────────────────────────────
    def write_json(self, data: dict, path: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)
        print(GREEN(f"  [+] JSON report saved → {path}"))


# ── CLI ────────────────────────────────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        description="SOC-Style PCAP Analyzer — beaconing, DNS exfil, HTTP anomaly, rare ports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python analyzer.py --demo
  python analyzer.py --pcap capture.pcap
  python analyzer.py --pcap capture.pcap --output json
  python analyzer.py --pcap capture.pcap --threshold 20 --output all
        """,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--pcap",  metavar="FILE",  help="Path to .pcap or .pcapng file")
    group.add_argument("--demo",  action="store_true", help="Run with synthetic demo data (no PCAP needed)")

    parser.add_argument(
        "--output", choices=["console", "csv", "json", "all"], default="all",
        help="Output format(s). Default: all",
    )
    parser.add_argument(
        "--threshold", type=int, default=15, metavar="N",
        help="Minimum packets per IP for beaconing analysis. Default: 15",
    )
    parser.add_argument(
        "--outdir", default="reports", metavar="DIR",
        help="Directory for CSV/JSON reports. Default: reports/",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    analyzer = PCAPAnalyzer(threshold=args.threshold)

    if args.demo:
        print(CYAN("\n[*] Loading synthetic demo data…"))
        analyzer.load_demo()
    else:
        if not os.path.isfile(args.pcap):
            print(RED(f"ERROR: File not found: {args.pcap}"))
            sys.exit(1)
        print(CYAN(f"\n[*] Loading {args.pcap}…"))
        analyzer.load_pcap(args.pcap)

    print(CYAN("[*] Analyzing…"))
    data = analyzer.analyze()

    reporter = Reporter()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    if args.output in ("console", "all"):
        reporter.print_report(data)

    if args.output in ("csv", "all"):
        reporter.write_csv(data, os.path.join(args.outdir, f"soc_report_{ts}.csv"))

    if args.output in ("json", "all"):
        reporter.write_json(data, os.path.join(args.outdir, f"soc_report_{ts}.json"))

    print()


if __name__ == "__main__":
    main()
