# SOC PCAP Analyzer

A Python-based PCAP analysis tool simulating real SOC analyst workflows. Performs **beaconing detection via interval variance analysis**, DNS exfiltration scoring, HTTP anomaly detection, and rare-port alerting — all mapped to MITRE ATT&CK TTPs. Outputs structured console, CSV, and JSON reports.

> Built as a portfolio project by Michael "Tony" Lee — SOC Analyst | MSSP | DFIR 

---

## Features

| Module | Detection Method | MITRE TTP |
|---|---|---|
| Beaconing | Coefficient of Variation (CV) on inter-packet intervals | T1071 |
| DNS Exfiltration | Shannon entropy + subdomain length scoring | T1048.003 |
| HTTP Anomalies | Keyword pattern matching against known offensive indicators | T1190 |
| Rare Port Usage | Destination port comparison against known C2/offensive ports | T1571 |
| Composite Risk Score | Weighted multi-signal scoring engine (0–100) | — |

### Why interval variance for beaconing?

Most simple beaconing detectors just count connections. The problem: legitimate software also generates high connection volumes (telemetry, update checks). 

Real C2 beaconing is distinguished by its **regularity** — malware phones home on a timer. This tool calculates the **Coefficient of Variation (CV = σ/μ)** of inter-packet intervals per IP:

- **CV < 0.10** → Highly regular → Strong beacon signature (score: 100)
- **CV 0.10–0.25** → Slightly jittered → Likely beacon (score: 80)
- **CV > 0.60** → Irregular → Likely benign traffic (score: 0)

This dramatically reduces false positives on high-volume legitimate hosts.

---

## Requirements

```bash
pip install pyshark pandas colorama
```

> **Note:** pyshark requires Wireshark/tshark to be installed on your system.  
> Download: https://www.wireshark.org/download.html

---

## Usage

```bash
# Analyze a PCAP file (outputs console + CSV + JSON)
python analyzer.py --pcap capture.pcap

# Run with synthetic demo data (no PCAP required)
python analyzer.py --demo

# Adjust beaconing sensitivity threshold
python analyzer.py --pcap capture.pcap --threshold 15

# Output formats: console, csv, json, all (default)
python analyzer.py --pcap capture.pcap --output json
```

---

## Sample Output

```
════════════════════════════════════════════════════════════
  SOC PCAP ANALYSIS REPORT
  File     : capture.pcap
  Analyzed : 2024-11-15T14:32:01Z
  Packets  : 3,142  |  Duration: 3600s
  Unique IPs: 9
════════════════════════════════════════════════════════════

[TOP TALKERS]
────────────────────────────────────────────────────────────
  192.168.1.105        312 conns  Risk: CRITICAL   Score: 82
  185.220.101.7        154 conns  Risk: HIGH       Score: 76
  10.0.0.44            187 conns  Risk: HIGH       Score: 55

[BEACONING ALERTS — T1071]
────────────────────────────────────────────────────────────
  [!] 185.220.101.7        Pkts: 154    Interval CV: 0.047    Beacon Score: 94/100
  [!] 192.168.1.105        Pkts: 312    Interval CV: 0.183    Beacon Score: 71/100

[DNS ANALYSIS — T1048.003]
────────────────────────────────────────────────────────────
  Total queries: 487  |  Unique domains: 38

  Suspicious (high entropy):
    [!] a2fghj3kl9mn0pq.exfil-domain.xyz          Entropy: 88/100
    [!] b3xyz8abc1def2ghi4jkl.tunnel.bad.io        Entropy: 79/100
```

---

## Architecture

```
analyzer.py
├── RiskEngine          # Weighted composite scoring (0-100)
│   ├── score_connection_volume()
│   ├── score_beacon_regularity()  # CV-based interval analysis
│   ├── score_dns_entropy()        # Shannon entropy + length
│   ├── score_rare_port()
│   └── composite()                # Weighted aggregate
│
├── BeaconDetector      # Per-IP timestamp tracking → CV analysis
├── DNSAnalyzer         # Query entropy scoring + known-benign filtering
├── PortAnalyzer        # Rare port detection → T1571
└── PCAPAnalyzer        # Orchestrator: load → analyze → report

---

## Report Outputs

- **Console** — Color-coded terminal output with risk scoring
- **CSV** → `reports/soc_report_<timestamp>.csv` — flat alert rows for SIEM ingestion
- **JSON** → `reports/soc_report_<timestamp>.json` — structured data for automation

---

## Roadmap

- [ ] Live capture mode (`--live eth0`)
- [ ] Lateral movement detection (internal-to-internal unusual ports)
- [ ] JA3/JA3S TLS fingerprinting
- [ ] VirusTotal IOC enrichment via API
- [ ] STIX 2.1 report export

---

## Certifications & Context

This project demonstrates concepts aligned with:
- CompTIA CySA+ (CS0-003) — Network analysis, threat detection
- MITRE ATT&CK for Enterprise — TTP mapping
- NIST SP 800-61 — Incident response workflow alignment

---

## Author

**Michael "Tony" Lee** — Information Security Analyst  
Warrenville, SC · [mlee30907@gmail.com](mailto:mlee30907@gmail.com)  
CompTIA Security+ · ISC2 CC · Cisco CyberOps Associate · CrowdStrike CCFA

---

## License

MIT — free to use, fork, and learn from.
