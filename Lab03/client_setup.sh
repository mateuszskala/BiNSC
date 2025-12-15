#!/bin/bash
echo "[INFO] Konfiguracja routingu..."

ip route del default 2>/dev/null || true
ip route del 172.22.0.0/24 2>/dev/null || true
ip route add 172.22.0.3/32 dev eth0
ip route add default via 172.22.0.3

echo "[INFO] Tablica routingu:"
ip route

echo "[INFO] Klient skonfigurowany"

tail -f /dev/null
