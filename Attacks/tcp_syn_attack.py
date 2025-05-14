from scapy.all import *

def syn_scan(target_ip, target_port):
    ans = sr1(IP(dst=target_ip)/TCP(dport=target_port, flags="S"), timeout=10, verbose=0)
    if ans:
        if ans.haslayer(TCP):
            if ans.getlayer(TCP).flags == 0x12:  # SYN-ACK
                send(IP(dst=target_ip)/TCP(dport=target_port, flags="R"), verbose=0)
                print(f"Port {target_port} is open")
            elif ans.getlayer(TCP).flags == 0x14:  # RST-ACK
                print(f"Port {target_port} is closed")
    else:
        print(f"Port {target_port} is filtered (no response)")

syn_scan("10.12.0.10", 80)