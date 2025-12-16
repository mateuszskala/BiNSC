# Scenariusz 4: Advanced HTTP/HTTPS Interception
        172.20.0.2                  172.20.0.3                      172.20.0.4
      mitm_client01             mitm_attacker01                  mitm_server01
      (Client)                  (Attacker / MITM)                (Server HTTP)
           |                         |                               |
           |  normalnie:             |                               |
           +------------------------>|------------------------------>+
           |      HTTP               |              HTTP             |

           |   w scenariuszu labu:   |                               |
           |                         |                               |
           +------------------------>|------------------------------>+
           |      HTTP (GET/POST)    |      HTTP do serwera          |
           |                         |                               |
           |<------------------------+<------------------------------+
           |   zmodyfikowany HTML    |   odpowiedź z serwera         |
           |   + wstrzyknięty JS     |   przechodzi przez mitmproxy  |

mitm_attacker01:
  - ARP spoofing między 172.20.0.2 a 172.20.0.4
  - iptables: przekierowanie portu 80 → 8080 (mitmproxy)
  - mitmproxy + intercept_advanced.py:
      * logowanie żądań/odpowiedzi do /app/logs
      * wstrzykiwanie JavaScript do odpowiedzi HTML
      * wyłapywanie loginów i haseł z POST

## Komponenty

-advanced_client (ofiara, 172.20.0.2)
-advanced_interceptor (proxy MITM, 172.20.0.3:8080)
-httpbin_server (serwer testowy, 172.20.0.4:8080)

## Pliki

- Dockerfile.advanced_interceptor obraz z mitmdump, iptables i narzedziami sieciowymi
- intercept_advanced.py skrypt mitmproxy logujący żądania/odpowiedzi i modyfikujący HTML
- docker-compose-scenario4.yml definicja usług: client, interceptor, web_server

## Uruchomienie (skrót)

Z katalogu `Lab04`:


docker compose -f docker-compose-scenario4.yml build
docker compose -f docker-compose-scenario4.yml up -d

## jak wygenerowac ruch:

docker exec -it advanced_client bash
apt update && apt install -y curl
curl -s -x http://172.20.0.3:8080 http://172.20.0.4:8080/get
curl -s -x http://172.20.0.3:8080 http://172.20.0.4:8080/post -d "username=ela&password=kot123"

## jak obejrzec logi:

docker exec -it advanced_interceptor bash
cat /app/logs/requests.log
cat /app/logs/responses.log
