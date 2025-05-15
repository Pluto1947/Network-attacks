# Network-attacks

## Overview

This document explains attacks and their respective mitigations in a controlled and isolated environment called MININET.

[Learn more about Mininet](http://mininet.org/)

## Basic Enterprise Network Protection

Firewall rules was applied using Nftables in the topology. Identifying the hosts under the Workstation, DMZ servers, and the Internet we initiated the rules during the topology startup.

### Note: The DMZ servers cannot send any ping or initiate any connection.

Before starting the cli, make sure the nft rules in the firewall folder is present at the /home/mininet directory, as this is the path in my updated topo.py to apply the rules during startup.

```bash
### NOTE: set the respective paths to the files on your system
### Start the mininet CLI
sudo -E python3 ~/LINFO2347/topo.py

### Ping all to confirm
sudo -E python3 ~/LINFO2347/topo.py -p

### Note: Remember to clean the environment, when you exit the cli before rerun.
sudo mn -c
```

## - ARP Cache Poisoning -

### Attack

ARP poisoning attacks require the attacker to have access to the local network. It's a protocol that enables the network communications to reach a specific device on the network.
This is a (MitM) attack that allows to intercept communication between network devices.
The attack works as follows:

```bash
### NOTE: This attack script poisons the gateway and the victim.
### NOTE: set the respective paths to the files on your system
### The Hosts maintain ARP cache and if it doesn't know the MAC address of a certain IP it sends ARP request packet asking other machines on the network for the matching MAC address.

###  Launch the attack to poison the cache belonging to the victim and router hosts.

###  Note: you have to input the host, host - interface, victim IP, gateway IP respectively.
 attacker python3 arp_poison.py -i interface -t victim_ip -g gateway_ip &

### Try to ping one of the DMZ servers from the victim host, you will notice the packets that are intended for the DMZ server is relayed to the attacker when you capture with a tool like wireshark.
victim ping -c 30 server_IP

### Check the ARP tables of the respective hosts to see the IP-MAC mapping.
host arp -n
```

### Mitigation

This approach is to use ARPtables to drop packets that don't match the legitimate IP-MAC mapping using --source-ip --source-mac, it applies this rule on a specific interface.
The mitigation works as follows:

```bash
### NOTE: set the respective paths to the files on your system
### you need to make the mitigation bash script executable with
sudo chown +x arp_mitigation.sh

### inside of the mininet cli, you will have to apply the mitigation on the victim host which was affected in the subnet. Edit the path to the script.
victim arp_mitigation.sh &

### rerun the attack and generate traffic to confirm the mitigation worked.
victim ping -c 30 server_IP

### Check the ARP tables of the respective hosts to see the IP-MAC mapping.
host arp -n

```

## - MAC/SWITCH flood (CAM TABLE) -

### Attack

This is a type of attack that is common in layer 2, The attacker simply fills up the CAM table of a switch with a very large number of ethernet frames. This frames are generated from a specific source IP but Random source MACs.
This forces the switch in a fail-open mode and acts like a hub.
A malicious user can use a packet analyzer to capture this packets that is transmitted between different devices.
The attack works as follows:

```bash
### NOTE: set the respective paths to the files on your system
### Make sure the script is executable
sudo chmod +x mac_flood.py

### From your the mininet cli
host python3 ~/project/mac_flood.py interface source_IP duration &

### Ping the Server from one of the host in the subnet, you will notice a huge packet loss and high latency.
victim ping -c 30 server_IP

```

### Mitigation

The mitigation intention is to populate the arp_table of the hosts in the subnet of the victim and learn their repsectivc IP-MAC mapping, Then it drops everyother packets that come from any other source MACs.
The mitigation works as follows:

```bash
### NOTE: set the respective paths to the files on your system
### Make sure the script is executable
sudo chmod +x mac_mitigation.sh

### From the mininet cli
host bash mac_mitigation.sh

### rerun the attack and generate traffic to confirm the mitigation worked.
victim ping -c 30 server_IP

```

## - SYN flood (HTTP) -

### Attack

• This attack intention is to overwhelm a target system's resources by exploiting the TCP handshake process, rendering it unable to respond to legitimate traffic. Eventually, the target cannot handle legitimate connections, causing a Denial-of-Service (DoS).
The Python script uses Scapy to launch a SYN flood attack (a type of Denial-of-Service attack) against a target IP (10.12.0.10) on port 80 (HTTP).
It spoofs source IPs from a subnet (10.1.0.0/24) to hide the real attacker IP (10.1.0.2).
The attack works as follows:

```bash
### NOTE: set the respective paths to the files on your system
### From the mininet cli capture the traffic from the target server then launch the attack
http tshark -i any -f "ttcp port 80" -w /tmp/syn_flood_attack.pcap &
ws2 python3 syn_flood.py

### By using fake IPs (10.1.0.0/24) the attacker appears to come from many sources, making it harder to block. And due to that, the target’s port 80 (HTTP) becomes unresponsive due to resource exhaustion.

```

## Mitigations

NFTable rules is applied on the victim host
This script mitigates SYN floods and limits HTTP connections while allowing legitimate traffic and logging attacks.

```bash
### NOTE: set the respective paths to the files on your system
### Make sure the script is executable
sudo chmod +x flood_protect.sh

### From the mininet cli
host flood_protect.sh

```

## - DHCP_starve_spoof -

### Attack

DHCP is a Network Protocol used to Automatically assign IP Information
This attacks aims to flood the DHCP server with bogus DHCP requests and leases all of the available IP addresses.
This can result in a DoS attack but a little bit of twist was added, which is after starving the server, we then add a rogue DHCP server which will replace the legitamate one and issue out IP addresses to clients.
Although the topology doesn't have an active DHCP server but the motive stands if there is a legitimate DHCP server present in the topology.
This creates a “man-in-the-middle” attack and can go entirely undetected as the intruder intercepts the data flow through the network.
The attack works as follow:

```bash
### NOTE: set the respective paths to the files on your system
### Make sure the script is executable
sudo chmod +x dhcp_starve_spoof.py

### From your the mininet cli
host python3 dhcp_starve_spoof.py -i interface &

### On the victim hosts in the subnet we release and renew DHCP to confirm the attack.
host dhclient -r interface
host dhclient interface

### check the IP details of the victim hosts
host ip a

```

### Mitigation

The motivation here is to protect against DHCP spoof, since we don't have an active DHCP server the Starve won't be much of a concern
If we are to allocate a server to the Switch subnet to act as the DHCP server, the
The mitigation works as follows:

```bash
### NOTE: set the respective paths to the files on your system
### Make sure the script is executable
sudo chmod +x dhcp_mitigate.sh

### From the mininet cli, R1 should be the host preferablly based on the topography.
host dhcp_mitigate.sh

### check the IP details of the victim hosts
host ip a

```

## - TCP SYN Scan -

### Attack

A SYN scan, also known as a half-open scan, is used to identify open ports on a target system. It is frequently employed during the pre-attack reconnaissance phase to map a network's attack surface. We will focus on executing this attack on a specific server in the network (HTTP Server). Below, we will explain how this attack is done.

The attacker sends TCP SYN packets to various ports on the target.

- If the target responds with a SYN-ACK, the port is open; the attacker usually sends a RST (reset) to close the connection without finishing the handshake.
- If the target sends a RST, the port is closed; if there’s no response, the port may be filtered (e.g., by a firewall).

- If the target sends again SYN-ACK, this means it's still waiting for the attacker to complete the handshake, which will not be done, and will permit the port to be kept open.
  The attack works as follow:

```bash
### NOTE: set the respective paths to the files on your system
### Make sure the script is executable
sudo chmod +x tcp_syn_attack.py

### From the mininet cli capture the traffic from the target server then launch the attack
host tshark -i any -f "tcp port 80" -w /tmp/tcp_scan_attack.pcap &
host python3 tcp_syn_attack.py

```

### Mitigation

To defend against TCP SYN Scan (half-open scan) attacks we will use nftable to implement protective measure.
The aim of this is to limit the number of SYN packets per time unit, restrict new connections to 10 per minute, which helps prevent rapid scanning, track IPs that send too many SYN packets, and block them for 60 seconds.
The mitigation works as follows:

```bash
### NOTE: set the respective paths to the files on your system
### From the mininet cli capture the traffic from the target server then launch the mitigation
host tshark -i any -f "tcp port 80" -w /tmp/tcp_scan_attack.pcap &
host sudo nft -f syn_protect.nft
### rerun the attack.... When we apply our ntftable rules on the HTTP server, we notice that the server state changes from OPEN to FILTERED. We will see what it looks like with Wireshark.

```
