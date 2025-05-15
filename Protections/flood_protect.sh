#!/usr/sbin/nft -f
flush ruleset

table inet http_filter {
    # Dynamic set to track SYN flooders
    set syn_flooders {
        type ipv4_addr
        flags timeout
        timeout 60s  # Block offenders for 60 seconds
    }

    chain input {
        type filter hook input priority 0; policy drop;

        # Allow established/related connections
        ct state established,related accept

        # Allow loopback and ICMP
        iif "lo" accept
        icmp type { echo-request, echo-reply } accept

        # ---- HTTP (Port 80) Protection ----
        tcp dport 80 tcp flags syn \
            add @syn_flooders { ip saddr } \
            limit rate 15/second burst 30 packets \
            counter \
            drop

        tcp dport 80 ct state new \
            limit rate 30/second burst 50 packets \
            accept

        # Log and drop other traffic
        counter log prefix "Blocked: " drop
    }
}