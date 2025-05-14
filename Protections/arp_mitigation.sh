#!/bin/bash

# Function to display usage
usage() {
    echo "Usage: $0 -i <interface> -p <protected_ip>"
    echo "  -i: Network interface to use (e.g., ws3-eth0)"
    echo "  -p: IP address to protect (e.g., 10.1.0.1 for gateway, 10.1.0.3 for victim)"
    exit 1
}

# Parse command-line arguments
while getopts "i:p:" opt; do
    case $opt in
        i) INTERFACE="$OPTARG" ;;
        p) PROTECTED_IP="$OPTARG" ;;
        ?) usage ;;
    esac
done

# Check if required arguments are provided
if [ -z "$INTERFACE" ] || [ -z "$PROTECTED_IP" ]; then
    usage
fi

# Function to resolve the legitimate MAC address
get_legit_mac() {
    # Ping to populate ARP cache
    ping -c1 "$PROTECTED_IP" > /dev/null 2>&1
    # Extract MAC from ARP cache
    arp -n -i "$INTERFACE" | awk -v ip="$PROTECTED_IP" '$1 == ip {print $3}' | head -n 1
}

# Function to apply arptables rules
apply_rules() {
    local legit_mac="$1"

    if [ -z "$legit_mac" ]; then
        echo "Error: Could not resolve MAC address for $PROTECTED_IP"
        exit 1
    fi

    echo "Legitimate MAC for $PROTECTED_IP: $legit_mac"

    # Flush existing arptables rules
    arptables -F

    # Drop ARP packets from the protected IP if they don't match the legitimate MAC
    arptables -A INPUT --source-ip "$PROTECTED_IP" ! --source-mac "$legit_mac" -i "$INTERFACE" -j DROP

    # Allow all other ARP traffic
    arptables -A INPUT -i "$INTERFACE" -j ACCEPT

    echo "arptables rules applied to protect $PROTECTED_IP on $INTERFACE."
}

# Function to clean up arptables rules
cleanup() {
    echo "Cleaning up arptables rules..."
    arptables -F
    # Clear ARP cache
    ip -s -s neigh flush dev "$INTERFACE"
    echo "ARP cache cleared on $INTERFACE."
}

# Main execution
echo "Starting ARP poisoning mitigation with arptables for $PROTECTED_IP on interface $INTERFACE..."

# Get the legitimate MAC address
legit_mac=$(get_legit_mac)

# Apply arptables rules
apply_rules "$legit_mac"

# Trap Ctrl+C to clean up
trap cleanup EXIT

# Keep the script running until interrupted
while true; do
    sleep 1
done