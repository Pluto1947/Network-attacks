#!/bin/bash

# Check if running as root
if [ "$(id -u)" != "0" ]; then
    echo "[!] This script must be run as root. Exiting..."
    exit 1
fi

# Check if arptables is available
if ! command -v arptables &> /dev/null; then
    echo "[!] arptables not found. Please install arptables (e.g., apt-get install arptables)."
    exit 1
fi

# Check if ping is available
if ! command -v ping &> /dev/null; then
    echo "[!] ping not found. Please install iputils-ping."
    exit 1
fi

# Determine the interface (assuming the first non-loopback interface)
INTERFACE=$(ip link | grep -v "lo:" | grep -oP '^[0-9]+: \K[^:@]+' | head -n 1)
if [ -z "$INTERFACE" ]; then
    echo "[!] No network interface found."
    exit 1
fi
echo "[*] Using interface: $INTERFACE"

# Learn the host's IP and subnet
echo "[*] Learning host's IP and subnet for $INTERFACE..."
IP_ADDR=$(ip -4 addr show $INTERFACE | grep inet | awk '{print $2}' | cut -d'/' -f1)
if [ -z "$IP_ADDR" ]; then
    echo "[!] Failed to learn IP address for $INTERFACE."
    exit 1
fi
NETMASK=$(ip -4 addr show $INTERFACE | grep inet | awk '{print $2}' | cut -d'/' -f2)
if [ -z "$NETMASK" ]; then
    echo "[!] Failed to learn netmask for $INTERFACE."
    exit 1
fi
# Calculate subnet CIDR (simplified for common netmasks)
if [ "$NETMASK" -eq 24 ]; then
    SUBNET=$(echo $IP_ADDR | cut -d'.' -f1-3).0/24
    SUBNET_BASE=$(echo $IP_ADDR | cut -d'.' -f1-3)
else
    echo "[!] Unsupported netmask: $NETMASK. Assuming /24 for now."
    SUBNET=$(echo $IP_ADDR | cut -d'.' -f1-3).0/24
    SUBNET_BASE=$(echo $IP_ADDR | cut -d'.' -f1-3)
fi
echo "[*] Host IP: $IP_ADDR, Subnet: $SUBNET"

# Ping all IPs in the subnet to populate ARP cache
echo "[*] Pinging all IPs in subnet $SUBNET to populate ARP cache..."
for i in {1..254}; do
    TARGET_IP="$SUBNET_BASE.$i"
    if [ "$TARGET_IP" != "$IP_ADDR" ]; then
        ping -c 2 -W 2 $TARGET_IP > /dev/null 2>&1 &
    fi
done
# Wait briefly for pings to complete and ARP cache to update
sleep 2

# Learn IP-MAC pairs of other hosts in the subnet
echo "[*] Learning IP-MAC pairs of other hosts in subnet $SUBNET..."
ARP_ENTRIES=$(ip neighbor show | grep "$INTERFACE" | grep -v "$IP_ADDR")
if [ -z "$ARP_ENTRIES" ]; then
    echo "[!] No ARP entries found for other hosts in subnet after pinging."
    exit 1
fi

# Flush existing arptables rules
echo "[*] Flushing existing arptables rules..."
arptables -F

# Configure arptables rules for each known IP-MAC pair
echo "[*] Setting up arptables rules on $INTERFACE..."
while read -r line; do
    PEER_IP=$(echo "$line" | awk '{print $1}')
    PEER_MAC=$(echo "$line" | awk '{print $5}')
    if [ -n "$PEER_IP" ] && [ -n "$PEER_MAC" ]; then
        echo "[*] Allowing ARP from IP: $PEER_IP, MAC: $PEER_MAC"
        arptables -A INPUT -i $INTERFACE --source-ip $PEER_IP --source-mac $PEER_MAC -j ACCEPT
    fi
done <<< "$ARP_ENTRIES"

# Drop all other ARP packets
arptables -A INPUT -i $INTERFACE -j DROP

# Verify rules
echo "[*] Verifying arptables configuration..."
arptables -L -v

echo "[*] arptables mitigation applied successfully on $INTERFACE."