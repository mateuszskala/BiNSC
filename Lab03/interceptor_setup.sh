#!/bin/bash

echo "[INFO] Configuring transparent proxy..."

FORWARD=$(cat /proc/sys/net/ipv4/ip_forward)
if [ "$FORWARD" -eq 1 ]; then
    echo "[OK] IP forwarding is enabled"
else
    echo "[ERROR] IP forwarding is not enabled"
    exit 1
fi

echo "[INFO] Setting up iptables rules..."

iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8080
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -A FORWARD -i eth0 -j ACCEPT

echo "[INFO] iptables rules configured:"
iptables -t nat -L -n -v

echo ""
echo "[INFO] Transparent proxy setup complete!"
echo "[INFO] You can now start mitmproxy with:"
echo "  mitmproxy -m transparent --listen-port 8080 -w /proxy/output/capture.mitm"
echo ""
echo "Or with custom script:"
echo "  mitmproxy -m transparent --listen-port 8080 -s /proxy/ssl_interceptor.py -w /proxy/output/capture.mitm"
