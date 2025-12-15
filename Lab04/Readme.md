# Scenariusz 4: Advanced HTTP/HTTPS Interception

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
