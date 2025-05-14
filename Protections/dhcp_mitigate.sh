#!/bin/bash

# Check if nftables is installed
if ! command -v nft &> /dev/null; then
    echo "Error: nftables is not installed. Please install nftables on r1."
    exit 1
fi

# Check for correct number of arguments
if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <subnet_cidr> <allowed_dhcp_server_ip> [<allowed_dhcp_server_ip> ...]"
    echo "Example: $0 10.1.0.0/24 10.1.0.1 10.12.0.1"
    exit 1
fi

# Get subnet and validate CIDR format
SUBNET="$1"
if ! echo "$SUBNET" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$'; then
    echo "Error: Invalid subnet format. Use CIDR notation (e.g., 10.1.0.0/24)."
    exit 1
fi

# Shift to process allowed DHCP server IPs
shift
ALLOWED_IPS=("$@")

# Validate each allowed IP
for IP in "${ALLOWED_IPS[@]}"; do
    if ! echo "$IP" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'; then
        echo "Error: Invalid IP address: $IP"
        exit 1
    fi
done

# Create temporary nftables ruleset file
TEMP_RULESET=$(mktemp)
cat > "$TEMP_RULESET" << EOF
flush ruleset

table inet dhcp_mitigate {
    chain input {
        type filter hook input priority 0; policy accept;
        # Drop rogue DHCP responses to r1 itself
        udp sport 67 ip saddr != { ${ALLOWED_IPS[*]} } drop
    }

    chain forward {
        type filter hook forward priority 0; policy accept;
        # Allow DHCP responses from allowed server IPs within subnet
        ip saddr { ${ALLOWED_IPS[*]} } udp sport 67 udp dport 68 accept
        # Block DHCP responses from IPs outside the subnet
        ip saddr != $SUBNET udp sport 67 udp dport 68 drop
    }

    chain output {
        type filter hook output priority 0; policy accept;
        # Drop rogue DHCP responses from r1 (if it acts as a server)
        udp sport 67 ip saddr != { ${ALLOWED_IPS[*]} } drop
    }
}
EOF

# Apply the ruleset
echo "Applying nftables rules on r1 to allow DHCP responses only from ${ALLOWED_IPS[*]} in subnet $SUBNET..."
if ! nft -f "$TEMP_RULESET"; then
    echo "Error: Failed to apply nftables ruleset."
    rm -f "$TEMP_RULESET"
    exit 1
fi

# Clean up
rm -f "$TEMP_RULESET"
echo "Rules applied successfully on r1. DHCP responses are restricted to ${ALLOWED_IPS[*]} within $SUBNET."