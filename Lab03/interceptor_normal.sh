#!/bin/bash

echo "============================================"
echo "  SCENARIUSZ 1: Normalny ruch HTTPS"
echo "============================================"
echo ""
echo "Monitorowanie ruchu sieciowego..."
echo "Nacisnij Ctrl+C aby zatrzymac"
echo ""

tcpdump -i eth0 -A 'tcp port 443 or tcp port 80'
