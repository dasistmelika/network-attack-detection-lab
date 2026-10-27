# Network Attack Detection Lab

An isolated VMware lab simulating common network attacks (port scanning,
SSH brute-force, ARP spoofing), with automated detection via Python/Scapy
and a live Streamlit dashboard mapped to MITRE ATT&CK.

## Architecture

- **Attacker VM**: Ubuntu Server (192.168.222.130)
- **Victim VM**: Ubuntu Server (192.168.222.128)
- **Network**: VMware Host-only (VMnet1), fully isolated from the internet

## Attack Scenarios

| Scenario | Tool | MITRE ATT&CK |
|---|---|---|
| Port Scan (SYN + Service) | Nmap | T1046 |
| SSH Brute-force | Hydra | T1110 |
| ARP Spoofing | Ettercap | T1557 |

## Detection Logic

`detection/detect.py` reads captured `.pcap` files and SSH auth logs,
applying rule-based detection:
- **Port Scan**: >10 distinct destination ports from one source IP
- **Brute-force**: ≥3 failed SSH login attempts from one source IP
- **ARP Spoofing**: same IP address observed with two different MAC addresses

Output is written to `alerts.csv` (timestamp, attack_type, src_ip, dst_ip,
severity, mitre_id, details).

## Dashboard

`dashboard/dashboard.py` is a Streamlit app visualizing:
- Alert summary metrics
- Attack timeline
- Attack type / source IP frequency charts
- Simple network topology (victim highlighted in red)
- Full alert table with MITRE ATT&CK tags

Run with:
```bash
streamlit run dashboard/dashboard.py
```

## Setup

See `lab-setup/` for VMware network configuration steps.

## Screenshots

See `screenshots/` for dashboard examples.
