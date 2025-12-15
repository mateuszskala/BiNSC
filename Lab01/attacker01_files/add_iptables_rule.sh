#!/bin/bash
# Enable IP forwarding
# sysctl -w net.ipv4.ip_forward=1

# Add iptables rule to redirect port 80 to mitmproxy
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080

echo "iptables rules added successfully"
iptables -L -t nat
