from mitmproxy import http
from datetime import datetime
import json


class SSLInterceptor:
    def __init__(self):
        self.request_count = 0

    def request(self, flow: http.HTTPFlow) -> None:
        self.request_count += 1

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n[{timestamp}] Request #{self.request_count}")
        print(f"  URL: {flow.request.pretty_url}")
        print(f"  Method: {flow.request.method}")
        print(f"  Host: {flow.request.host}")
        print(f"  Scheme: {flow.request.scheme}")

        print(f"  Headers:")
        for key, value in flow.request.headers.items():
            print(f"    {key}: {value}")

        if flow.request.method == "POST":
            try:
                content = flow.request.get_text()
                print(f"  Body: {content[:200]}")
            except:
                print(f"  Body: [Binary data]")

    def response(self, flow: http.HTTPFlow) -> None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n[{timestamp}] Response")
        print(f"  URL: {flow.request.pretty_url}")
        print(f"  Status: {flow.response.status_code}")
        print(f"  Content-Type: {flow.response.headers.get('content-type', 'unknown')}")
        print(f"  Content-Length: {len(flow.response.content)} bytes")

        flow.response.headers["X-Intercepted-By"] = "MitM-Lab03"


addons = [SSLInterceptor()]
