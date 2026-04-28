# SOC-Style-PCAP-Analyzer-v2-Upgraded-
Built a Python-based PCAP analysis tool simulating SOC workflows, including beaconing detection, anomaly scoring, and automated reporting aligned with MITRE ATT&amp;CK.
pip install pyshark pandas

import pyshark
import pandas as pd
from collections import Counter, defaultdict

PCAP_FILE = "sample.pcap"


# -----------------------------
# Helper: Simple risk scoring
# -----------------------------
def calculate_risk(count):
    if count > 100:
        return "HIGH"
    elif count > 30:
        return "MEDIUM"
    else:
        return "LOW"


# -----------------------------
# Main Analyzer
# -----------------------------
def analyze_pcap(file):
    print("\n[+] Loading PCAP...\n")

    cap = pyshark.FileCapture(file, only_summaries=True)

    ip_counter = Counter()
    dns_counter = Counter()
    http_counter = Counter()

    packet_data = []

    for packet in cap:
        try:
            info = packet.info.lower()

            # crude IP extraction
            if "->" in info:
                parts = info.split("->")
                src = parts[0].strip().split()[-1]
                dst = parts[1].strip().split()[0]

                ip_counter[src] += 1
                ip_counter[dst] += 1

                packet_data.append({
                    "source": src,
                    "destination": dst,
                    "info": info
                })

            # DNS detection
            if "dns" in info:
                dns_counter[info] += 1

            # HTTP detection
            if "http" in info:
                http_counter[info] += 1

        except:
            continue

    cap.close()

    # -----------------------------
    # BEACONING DETECTION
    # -----------------------------
    beacon_alerts = []
    for ip, count in ip_counter.items():
        if count > 20:  # simple heuristic
            beacon_alerts.append({
                "ip": ip,
                "connections": count,
                "risk": calculate_risk(count),
                "mitre": "T1071 - Application Layer Protocol (Possible C2)"
            })

    # -----------------------------
    # OUTPUT REPORT
    # -----------------------------
    print("\n========== SOC ANALYSIS REPORT ==========\n")

    print(f"Total Unique IPs: {len(ip_counter)}")

    print("\n[Top Talkers]")
    for ip, count in ip_counter.most_common(5):
        print(f"{ip} -> {count} connections | Risk: {calculate_risk(count)}")

    print("\n[DNS Activity]")
    for dns, count in dns_counter.most_common(3):
        print(f"{dns[:80]}... ({count})")

    print("\n[HTTP Activity]")
    for http, count in http_counter.most_common(3):
        print(f"{http[:80]}... ({count})")

    print("\n[🚨 Beaconing / C2 Suspicion]")
    for b in beacon_alerts:
        print(f"{b['ip']} -> {b['connections']} connections | {b['risk']} | {b['mitre']}")

    # -----------------------------
    # EXPORT CSV (SOC STYLE REPORT)
    # -----------------------------
    df = pd.DataFrame(beacon_alerts)
    df.to_csv("soc_report.csv", index=False)

    print("\n[+] Report exported to soc_report.csv")
    print("=========================================\n")


if __name__ == "__main__":
    analyze_pcap(PCAP_FILE)
