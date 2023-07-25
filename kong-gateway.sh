#!/bin/bash
docker rm -f kong-gateway-icap

docker run -d --name kong-gateway-icap \
 --network=kong-net \
 --mount type=bind,source="$(pwd)"/kong/plugins/icap,destination=/usr/local/share/lua/5.1/kong/plugins/icap \
 -e "KONG_DATABASE=postgres" \
 -e "KONG_PG_HOST=kong-database-icap" \
 -e "KONG_PG_USER=kong" \
 -e "KONG_PG_PASSWORD=kongpass" \
 -e "KONG_PROXY_ACCESS_LOG=/dev/stdout" \
 -e "KONG_ADMIN_ACCESS_LOG=/dev/stdout" \
 -e "KONG_PROXY_ERROR_LOG=/dev/stderr" \
 -e "KONG_ADMIN_ERROR_LOG=/dev/stderr" \
 -e "KONG_ADMIN_LISTEN=0.0.0.0:8001" \
 -e "KONG_ADMIN_GUI_URL=http://localhost:8002" \
 -e "KONG_PLUGINS=bundled,icap" \
 -e KONG_LICENSE_DATA \
 -p 8000:8000 \
 -p 8443:8443 \
 -p 8001:8001 \
 -p 8444:8444 \
 -p 8002:8002 \
 -p 8445:8445 \
 -p 8003:8003 \
 -p 8004:8004 \
 kong/kong-gateway:3.3.0.0

 echo 'docker logs -f kong-gateway-icap'