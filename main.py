import sys
from pathlib import Path
from collections import defaultdict, Counter
from datetime import datetime
from typing import Dict, List, Set, Tuple

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, DNS, Raw
    from scapy.error import Scapy_Exception
except ImportError:
    print("\n[!]Error: scapy not installed. Run: pip install scapy\n")
    sys.exit(1)

THRESHOLDS = {
    'port_scan_ports':10,
    'port_scan_time':60,
    'syn_scan_time':50,
    'udp_scan_time':100,
    'icmp_flood_count':50,
    'bruteforce_attempts':5,
    'dns_subdomain_count':20,
    'ping_of_death_size':65535
}

SQL_INJECTION_PATTERNS = [
    b"' OR '1'='1",
    b"' OR 1=1--",
    b"admin'--",
    b"' UNION SELECT",
    b"; DROP TABLE",
    b"' OR 'x'='x",
    b"1' AND '1'='1",
]

XSS_PATTERNS = [
    b"<script>alert(",
    b"<script>document.cookie",
    b"javascript:",
    b"onerror=",
    b"onload=",
    b"<iframe",
]

CMD_INJECTION_PATTERNS = [
    b"; cat /etc/passwd",
    b"| whoami",
    b"; ls -la",
    b"&& id",
    b"`cat /etc/shadow`",
    b"$(uname -a)",
]


class Alert:
    def __init__(self, severity: str, attack_type: str, details: str,
                 src_ip: str = None, dst_ip: str = None, timestamp: float = None):
        self.severity = severity
        self.attack_type = attack_type
        self.details = details
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.timestamp = timestamp

    def __repr__(self):
        return f"[{self.severity}] {self.attack_type}: {self.details}"


class IDSEngine:
    def __init__(self):
        self.syn_tracker = defaultdict(list)
        self.port_scan_tracker = defaultdict(set)
        self.syn_flood_tracker = defaultdict(int)
        self.udp_flood_tracker = defaultdict(int)
        self.icmp_flood_tracker = defaultdict(int)
        self.arp_table = {}
        self.dns_queries = defaultdict(set)
        self.service_attempts = defaultdict(set)
        self.alerts: List[Alert] = []
        self.packet_count = 0
        self.protocol_stats = Counter()


    def analyze_pcap(self, pcap_file: str):
        print(f"[*] Loading packets from {pcap_file}")
        try:
            packets = rdpcap(pcap_file)
        except FileNotFoundError:
            print(f"[!] File {pcap_file} not found")
            sys.exit(1)
        except Scapy_Exception:
            print(f"[!] Error reading {pcap_file}")
            sys.exit(1)

        print(f"[*] TOTAL PACKETS: {len(packets)}")
        print("Analyzing packets...\n")

        for packet in packets:
            self.packet_count += 1
            self.analyze_packet(packet)

        self.detect_port_scans()
        self.detect_floods()
        self.detect_dns_tunneling()
        self.detect_bruteforce()

    def analyze_packet(self, packet):
        if IP in packet:
            self.protocol_stats["IP"] += 1

            if TCP in packet:
                self.protocol_stats["TCP"] += 1
                self.analyze_tcp(packet)

            elif UDP in packet:
                self.protocol_stats["UDP"] += 1
                self.analyze_udp(packet)

            elif ICMP in packet:
                self.protocol_stats["ICMP"] += 1
                self.analyze_icmp(packet)

        if ARP in packet:
            self.protocol_stats["ARP"] += 1
            self.analyze_arp(packet)

        if Raw in packet:
            self.analyze_payload(packet)


    def analyze_tcp(self, packet):
        tcp = packet[TCP]
        ip = packet[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        dst_port = tcp.dport
        flags = tcp.flags
        timestamp = float(packet.time)

        if flags & 0x02:
            self.syn_tracker[src_ip].append((timestamp, dst_port, dst_ip))
            self.port_scan_tracker[src_ip].add(dst_port)

        if flags == 0:
            self.alerts.append(Alert(
                'HIGH', 'NULL Scan',
                f'NULL scan detected on {src_ip} to {dst_ip}:{dst_port}',
                src_ip, dst_ip, timestamp
            ))

        if flags & 0x29 == 0x29:
            self.alerts.append(Alert(
                'HIGH', 'XMAS Scan',
                f'XMAS scan detected on {src_ip} to {dst_ip}:{dst_port}',
                src_ip, dst_ip, timestamp
            ))

        if flags & 0x02 and not (flags & 0x10):
            self.syn_flood_tracker[dst_ip] += 1

        bruteforce_ports = {22: 'SSH', 21: 'FTP', 23: 'Telnet'}
        if dst_port in bruteforce_ports:
            service = bruteforce_ports[dst_port]
            self.service_attempts[(src_ip, dst_ip, service)] += 1


    def analyze_udp(self, packet):
        udp = packet[UDP]
        ip = packet[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        dst_port = udp.dport

        self.udp_flood_tracker[dst_ip] += 1

        if DNS in packet and dst_port == 53:
            self.analyze_dns(packet)


    def analyze_icmp(self, packet):
        icmp = packet[ICMP]
        ip = packet[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        timestamp = float(packet.time)

        self.icmp_flood_tracker[dst_ip] += 1
        if len(packet) > THRESHOLDS['ping_of_death_size']:
            self.alerts.append(Alert(
                'CRITICAL', 'Ping of Death',
                f'Oversized ICMP packet ({len(packet)} bytes) from {src_ip} to {dst_ip}',
                src_ip, dst_ip, timestamp
            ))


    def analyze_arp(self, packet):
        arp = packet[ARP]

        if arp.op == 2:
            ip = arp.psrc
            mac = arp.hwsrc

            if ip in self.arp_table and self.arp_table[ip] != mac:
                self.alerts.append(Alert(
                    'CRITICAL', 'ARP Spoofing',
                    f'ARP spoofing detected! IP {ip} changed MAC from {self.arp_table[ip]} to {mac}',
                    src_ip=ip
                ))

    def analyze_dns(self, packet):
        dns = packet[DNS]
        if dns.qd:
            query_name = dns.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
            parts = query_name.split('.')
            if len(parts) >= 2:
                base_domain = '.'.join(parts[-2:])
                subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else ''
                if subdomain:
                    self.dns_queries[base_domain].add(subdomain)


    def analyze_payload(self, packet):
        try:
            payload = bytes(packet[Raw].load).lower()
        except:
            return
        ip = packet[IP] if IP in packet else None
        if not ip:
            return
        src_ip = ip.src
        dst_ip = ip.dst
        timestamp = float(packet.time)
        for pattern in SQL_INJECTION_PATTERNS:
            if pattern.lower() in payload:
                self.alerts.append(Alert(
                    'CRITICAL', 'SQL Injection Attempt',
                    f'SQL injection pattern detected: {pattern.decode("utf-8", errors="ignore")}',
                    src_ip, dst_ip, timestamp
                ))
                break
        for pattern in XSS_PATTERNS:
            if pattern.lower() in payload:
                self.alerts.append(Alert(
                    'HIGH', 'XSS Attempt',
                    f'XSS pattern detected: {pattern.decode("utf-8", errors="ignore")}',
                    src_ip, dst_ip, timestamp
                ))
                break
        for pattern in CMD_INJECTION_PATTERNS:
            if pattern.lower() in payload:
                self.alerts.append(Alert(
                    'CRITICAL', 'Command Injection Attempt',
                    f'Command injection pattern detected: {pattern.decode("utf-8", errors="ignore")}',
                    src_ip, dst_ip, timestamp
                ))
                break

    def detect_port_scans(self):
        for src_ip, syn_data in self.syn_tracker.items():
            unique_ports = len(self.port_scan_tracker[src_ip])
            if unique_ports > THRESHOLDS['port_scan_ports']:
                timestamps = [t for t, _, _ in syn_data]
                time_span = max(timestamps) - min(timestamps)
                if time_span <= THRESHOLDS['port_scan_time']:
                    target_ips = {dst_ip for _, _, dst_ip in syn_data}
                    self.alerts.append(Alert(
                        'HIGH', 'Port Scan',
                        f'Port scan detected from {src_ip} scanning {unique_ports} ports '
                        f'on {len(target_ips)} target(s) in {time_span:.1f}s',
                        src_ip=src_ip
                    ))


    def detect_floods(self):
        for dst_ip, count in self.syn_flood_tracker.items():
            if count > THRESHOLDS['syn_scan_time']:
                self.alerts.append(Alert(
                    'CRITICAL', 'SYN Flood',
                    f'SYN flood detected against {dst_ip} ({count} SYN packets)',
                    dst_ip=dst_ip
                ))
        for dst_ip, count in self.udp_flood_tracker.items():
            if count > THRESHOLDS['udp_scan_time']:
                self.alerts.append(Alert(
                    'CRITICAL', 'UDP Flood',
                    f'UDP flood detected against {dst_ip} ({count} UDP packets)',
                    dst_ip=dst_ip
                ))
        for dst_ip, count in self.icmp_flood_tracker.items():
            if count > THRESHOLDS['icmp_flood_count']:
                self.alerts.append(Alert(
                    'HIGH', 'ICMP Flood',
                    f'ICMP flood detected against {dst_ip} ({count} ICMP packets)',
                    dst_ip=dst_ip
                ))


    def detect_dns_tunneling(self):
        for base_domain, subdomains in self.dns_queries.items():
            if len(subdomains) > THRESHOLDS['dns_subdomain_count']:
                self.alerts.append(Alert(
                    'HIGH', 'DNS Tunneling',
                    f'Possible DNS tunneling detected for {base_domain} '
                    f'({len(subdomains)} unique subdomains)',
                ))


    def detect_bruteforce(self):
        for (src_ip, dst_ip, service), count in self.service_attempts.items():
            if count > THRESHOLDS['brute_force_attempts']:
                self.alerts.append(Alert(
                    'CRITICAL', f'{service} Brute Force',
                    f'Brute force attack detected from {src_ip} to {dst_ip} '
                    f'on {service} ({count} attempts)',
                    src_ip, dst_ip
                ))

def print_banner():
    print("\n" + "=" * 80)
    print("LIGHTWEIGHT INTRUSION DETECTION SYSTEM (IDS)")
    print(rf"""
      _ ___  ____ 
     | |   \/ ___|
     | | |\ |___ \ 
     | | |/_|___) |
     |_|___/|____/ 
    SHIELD ACTIVATED
    """ + rf"""
      _________________________
     /                         \
    |   _____________________   |
    |  |    NETWORK TRAFFIC  |  |
    |  |       >>>>>>>>>     |  |
    |  |_____________________|  |
    |      ______||_______      |
    |     |               |     |
    |     |   INTRUSION   |     |
    |     |   DETECTION   |     |
    |     |    SYSTEM     |     |
    |     |_______________|     |
    \____________||____________/
          _______||_______
         |  [!] ALERT [!] |
	  \______________/
    """)
    print("=" * 80)

def print_summary(engine, pcap_file):
    print("\n" + "─" * 80)
    print("    ANALYSIS SUMMARY")
    print("─" * 80)
    print(f"   File           : {pcap_file}")
    print(f"   Total Packets  : {engine.packet_count}")
    print(f"   Protocol Stats : {dict(engine.protocol_stats)}")
    print(f"   Total Alerts   : {len(engine.alerts)}")
    severity_count = Counter(alert.severity for alert in engine.alerts)
    print(f"\n   Alerts by Severity:")
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = severity_count.get(severity, 0)
        if count > 0:
            print(f"       {severity:<10} : {count}")
    if engine.alerts:
        print("\n" + "─" * 80)
        print("    SECURITY ALERTS")
        print("─" * 80 + "\n")
        alerts_by_type = defaultdict(list)
        for alert in engine.alerts:
            alerts_by_type[alert.attack_type].append(alert)
        for attack_type, alerts in sorted(alerts_by_type.items()):
            print(f"   [{alerts[0].severity}] {attack_type} ({len(alerts)} alert(s))")
            for i, alert in enumerate(alerts[:5], 1):
                details = alert.details
                if alert.src_ip:
                    details += f" [SRC: {alert.src_ip}]"
                if alert.dst_ip:
                    details += f" [DST: {alert.dst_ip}]"
                print(f"      {i}. {details}")
            if len(alerts) > 5:
                print(f"      ... and {len(alerts) - 5} more")
            print()
    else:
        print("\n    No threats detected in this capture file!\n")
        print("=" * 80 + "\n")

def main():
    print_banner()
    if len(sys.argv) < 2:
        print("\n   Usage: python ids.py <pcap_file>")
        print("   Example: python ids.py capture.pcap\n")
    else:
        pcap_file = sys.argv[1]
    if not Path(pcap_file).exists():
        print(f"\nError: File not found: {pcap_file}\n")
        sys.exit(1)
    engine = IDSEngine()
    engine.analyze_pcap(pcap_file)
    print_summary(engine, pcap_file)

if __name__ == "__main__":
    main()
