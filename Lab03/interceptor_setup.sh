#!/bin/bash

echo "=== Konfiguracja posrednika SSL ==="

echo "Wlaczanie przekazywania IP..."
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "Przekazywanie IP ustawione przez docker-compose"

echo "Konfiguracja iptables..."
iptables -t nat -F PREROUTING
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8080

echo "Reguly iptables:"
iptables -t nat -L PREROUTING -n -v | grep REDIRECT

echo ""
echo "Uruchamianie mitmdump na porcie 8080..."
echo "Plik: /proxy/output/capture.mitm"
echo "Nacisnij Ctrl+C aby zatrzymac"
echo ""

mitmdump -m transparent --listen-port 8080 \
  -s /proxy/ssl_interceptor.py \
  -w /proxy/output/capture.mitm
