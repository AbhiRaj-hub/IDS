# 🛡️ Lightweight IDS (Python Version)

A high-performance, signature-based Intrusion Detection System (IDS) written in Python using **Scapy**. This tool analyzes `.pcap` files to detect common network attacks through packet-level inspection and behavioral analysis.

## 🚀 Features

* **DDoS Detection**: Identifies SYN, UDP, and ICMP flood patterns.
* **Scanning Detection**: Spots TCP port scanning (SYN, NULL, XMAS, FIN).
* **DNS Analysis**: Detects potential DNS tunneling by monitoring unique subdomain entropy.
* **Web Attack Signatures**: Uses pattern matching to find SQL Injection (SQLi), Cross-Site Scripting (XSS), and Command Injection.
* **Brute Force Detection**: Tracks failed or rapid login attempts for SSH, FTP, and Telnet.

## 🛠️ Prerequisites

Before running the IDS, ensure you have Python 3.8+ and the following dependencies installed:
pip install scapy

## 💻 Usage

Basic Analysis
To analyze an existing capture file:
python ids.py capture.pcap

## 📊 Analysis Workflow
The IDS engine follows a multi-stage pipeline:
Ingestion: Reading packets via Scapy.
Protocol Decoding: Breaking down Ethernet, IP, TCP, UDP, and ICMP layers.
Signature Matching: Checking payloads against known malicious patterns.
Threshold Analysis: Evaluating frequency-based attacks (floods and scans).
Reporting: Generating a formatted security summary.

## ⚙️ Configuration
You can adjust detection sensitivity by modifying the THRESHOLDS dictionary in the source code
Parameter	                    Default Value	                        Description
syn_flood_count	                          50	                   Max SYN packets per destination
port_scan_ports	                          10	                   Unique ports scanned before alerting
brute_force_attempts	                   5	                   Login attempts allowed per service

Adding Custom Signatures
To add a new detection category, follow this structure:
Define the Patterns: Add a new list of strings or byte patterns (e.g., LOG4J_PATTERNS).
Update the Loop: Add a loop in analyze_payload to check the current packet against these patterns.
Define Severity: Map the new attack to a severity level (Critical/High/Medium).

## ⚖️ License
This project is open-source. Feel free to modify the signatures to suit your network environment.
