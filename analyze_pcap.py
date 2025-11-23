#!/usr/bin/env python3
"""
------------------------------------------------------------
 Wireshark Packet Analysis Tool
------------------------------------------------------------
 Author      : Dhanush
 Description : Analyzes .pcap files to extract packet counts,
               top protocols, IPs, and port statistics.
 Environment : Kali Linux / Ubuntu / Windows (Python 3)
 Dependencies: scapy, tabulate, colorama
------------------------------------------------------------
"""

from scapy.all import rdpcap
from collections import Counter
from tabulate import tabulate
from colorama import Fore, Style, init
import argparse
import os
import sys

init(autoreset=True)

# ------------------------------------------------------------
# Argument Parser
# ------------------------------------------------------------
parser = argparse.ArgumentParser(
    description="Analyze a Wireshark .pcap file for protocol and IP statistics."
)
parser.add_argument("pcap_file", help="Path to the .pcap file to analyze")
args = parser.parse_args()

if not os.path.exists(args.pcap_file):
    print(Fore.RED + f"[!] File not found: {args.pcap_file}")
    sys.exit(1)

print(Fore.CYAN + Style.BRIGHT + "\n🔍 Starting Packet Capture Analysis")
print(Fore.CYAN + f"File: {args.pcap_file}")
print(Fore.CYAN + "-" * 60)

# ------------------------------------------------------------
# Load Packets
# ------------------------------------------------------------
try:
    packets = rdpcap(args.pcap_file)
except Exception as e:
    print(Fore.RED + f"[!] Error reading file: {e}")
    sys.exit(1)

total_packets = len(packets)
print(Fore.GREEN + f"✅ Total packets captured: {total_packets}\n")

# ------------------------------------------------------------
# Analyze Packets
# ------------------------------------------------------------
protocols = Counter()
src_ips = Counter()
dst_ips = Counter()
ports = Counter()

for pkt in packets:
    try:
        layer = pkt.summary().split()[0]
        protocols[layer] += 1

        if pkt.haslayer("IP"):
            src_ips[pkt["IP"].src] += 1
            dst_ips[pkt["IP"].dst] += 1
            if pkt.haslayer("TCP"):
                ports[pkt["TCP"].dport] += 1
            elif pkt.haslayer("UDP"):
                ports[pkt["UDP"].dport] += 1
    except Exception:
        continue

# ------------------------------------------------------------
# Display Results
# ------------------------------------------------------------
def print_table(title, headers, data):
    print(Fore.YELLOW + f"\n📊 {title}")
    print(tabulate(data, headers=headers, tablefmt="fancy_grid"))


# Protocol Summary
proto_table = [
    [proto, count, f"{(count / total_packets) * 100:.2f}%"]
    for proto, count in protocols.most_common(8)
]
print_table("Top Protocols", ["Protocol", "Packets", "Percentage"], proto_table)

# Source IPs
src_table = [[ip, count] for ip, count in src_ips.most_common(5)]
print_table("Top Source IPs", ["Source IP", "Packets"], src_table)

# Destination IPs
dst_table = [[ip, count] for ip, count in dst_ips.most_common(5)]
print_table("Top Destination IPs", ["Destination IP", "Packets"], dst_table)

# Ports
port_table = [[port, count] for port, count in ports.most_common(5)]
print_table("Top Destination Ports", ["Port", "Packets"], port_table)

# ------------------------------------------------------------
# Summary
# ------------------------------------------------------------
print(Fore.CYAN + "\n🧾 Summary Report")
print(Fore.CYAN + "-" * 60)
print(
    f"""
• Total Packets Captured  : {total_packets}
• Unique Protocols Found  : {len(protocols)}
• Unique Source IPs       : {len(src_ips)}
• Unique Destination IPs  : {len(dst_ips)}
• Unique Destination Ports: {len(ports)}

✅ Analysis Completed Successfully!
"""
)
print(Fore.CYAN + "-" * 60)
print(Fore.GREEN + "Tip: You can redirect this output to a file:")
print(Fore.WHITE + "   python3 analyze_pcap.py capture.pcap > report.txt\n")

