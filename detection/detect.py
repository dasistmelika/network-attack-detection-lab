from scapy.all import rdpcap, TCP, IP, ARP
from collections import defaultdict
import csv
import re
from datetime import datetime

alerts = []

print("[*] Analyzing Nmap scan pcap...")
packets = rdpcap("nmap_scan.pcap")

syn_tracker = defaultdict(set)
first_seen = {}

for pkt in packets:
    if pkt.haslayer(TCP) and pkt.haslayer(IP) and pkt[TCP].flags == "S":
        src = pkt[IP].src
        dport = pkt[TCP].dport
        syn_tracker[src].add(dport)
        if src not in first_seen:
            first_seen[src] = datetime.fromtimestamp(float(pkt.time)).strftime("%Y-%m-%d %H:%M:%S")

for src, ports in syn_tracker.items():
    if len(ports) > 10:
        alerts.append({
            "timestamp": first_seen[src],
            "attack_type": "Port Scan",
            "src_ip": src,
            "dst_ip": "192.168.222.128",
            "severity": "Medium",
            "mitre_id": "T1046",
            "details": f"{len(ports)} distinct ports probed"
        })

print(f"    Found {len([a for a in alerts if a['attack_type']=='Port Scan'])} port scan alert(s)")

print("[*] Analyzing SSH brute-force log...")

failed_attempts = []
with open("ssh_bruteforce_log.txt", "r") as f:
    for line in f:
        if "Failed password" in line:
            match = re.search(r"(\w+\s+\d+\s+[\d:]+).*from\s+([\d.]+)", line)
            if match:
                failed_attempts.append({
                    "time_str": match.group(1),
                    "src_ip": match.group(2)
                })

ip_fail_count = defaultdict(int)
for attempt in failed_attempts:
    ip_fail_count[attempt["src_ip"]] += 1

for ip, count in ip_fail_count.items():
    if count >= 3:
        alerts.append({
            "timestamp": failed_attempts[0]["time_str"] if failed_attempts else "N/A",
            "attack_type": "SSH Brute-force",
            "src_ip": ip,
            "dst_ip": "192.168.222.128",
            "severity": "High",
            "mitre_id": "T1110",
            "details": f"{count} failed login attempts"
        })

print(f"    Found {len([a for a in alerts if a['attack_type']=='SSH Brute-force'])} brute-force alert(s)")

print("[*] Analyzing ARP spoofing pcap...")
arp_packets = rdpcap("arp_spoof_simulated.pcap")

mac_ip_map = {}
for pkt in arp_packets:
    if pkt.haslayer(ARP) and pkt[ARP].op == 2:
        ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc
        if ip in mac_ip_map and mac_ip_map[ip] != mac:
            alerts.append({
                "timestamp": datetime.fromtimestamp(float(pkt.time)).strftime("%Y-%m-%d %H:%M:%S"),
                "attack_type": "ARP Spoofing",
                "src_ip": ip,
                "dst_ip": "192.168.222.128",
                "severity": "High",
                "mitre_id": "T1557",
                "details": f"MAC changed from {mac_ip_map[ip]} to {mac}"
            })
        mac_ip_map[ip] = mac

print(f"    Found {len([a for a in alerts if a['attack_type']=='ARP Spoofing'])} ARP spoofing alert(s)")

if alerts:
    with open("alerts.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=alerts[0].keys())
        writer.writeheader()
        writer.writerows(alerts)
    print(f"\n[+] Saved {len(alerts)} total alerts to alerts.csv")
else:
    print("\n[!] No alerts generated - check your pcap/log files")
