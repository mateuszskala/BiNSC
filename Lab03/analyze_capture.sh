#!/bin/bash

echo "=== Lab03 SSL Stripping Analysis ==="
echo ""

if [ ! -f "./proxy_output/capture.mitm" ]; then
    echo "[ERROR] Capture file not found at ./proxy_output/capture.mitm"
    echo "Please ensure mitmproxy has been stopped (to flush data) and try again."
    exit 1
fi

FILESIZE=$(stat -f%z "./proxy_output/capture.mitm" 2>/dev/null || stat -c%s "./proxy_output/capture.mitm" 2>/dev/null)
echo "Capture file size: $FILESIZE bytes"
echo ""

if [ "$FILESIZE" -eq 0 ]; then
    echo "[ERROR] Capture file is empty!"
    echo "Make sure to:"
    echo "  1. Run mitmproxy with -w flag"
    echo "  2. Send traffic through the proxy"
    echo "  3. Quit mitmproxy (press 'q') to flush data"
    exit 1
fi

echo "[INFO] Analyzing captured traffic..."
echo ""

echo "=== Flow Summary ==="
docker exec ssl_interceptor mitmdump -n -r /proxy/output/capture.mitm 2>/dev/null | head -50

echo ""
echo "=== Detailed Analysis with Verbose Output ==="
docker exec ssl_interceptor mitmdump -n -r /proxy/output/capture.mitm -v 2>/dev/null | head -100

echo ""
echo "=== Exporting to HAR format ==="
docker exec ssl_interceptor mitmdump -n -r /proxy/output/capture.mitm --set hardump=/proxy/output/capture.har 2>/dev/null
echo "[INFO] Exported to ./proxy_output/capture.har"

echo ""
echo "=== Copying files to host ==="
docker cp ssl_interceptor:/proxy/output/capture.mitm ./proxy_output/ 2>/dev/null
docker cp ssl_interceptor:/proxy/output/capture.har ./proxy_output/ 2>/dev/null
echo "[INFO] Files copied to ./proxy_output/"

echo ""
echo "=== Analysis Complete ==="
echo "Files available:"
ls -lh ./proxy_output/
