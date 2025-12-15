#!/bin/bash

echo "[INFO] Configuring routing for transparent proxy..."

ip route del default 2>/dev/null || true
ip route add default via 172.22.0.3

echo "[INFO] Current routing table:"
ip route

echo "[INFO] Client is now configured to route all traffic through interceptor (172.22.0.3)"
echo "[INFO] All HTTP/HTTPS traffic will be transparently intercepted"

tail -f /dev/null
