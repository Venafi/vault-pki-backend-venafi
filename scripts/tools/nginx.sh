#!/bin/bash
ROLE=$1
PORT=$2
cont=vault-demo-nginx-${ROLE}

docker rm -f $cont || echo "Container $cont doesn't exists"
docker run --name $cont -v $(pwd)/scripts/config/nginx/nginx.conf:/etc/nginx/conf.d/default.conf:ro \
    -v $(pwd)/scripts/config/nginx/cert/${ROLE}-nginx.key:/etc/nginx/ssl/nginx.key \
    -v $(pwd)/scripts/config/nginx/cert/${ROLE}-nginx.crt:/etc/nginx/ssl/nginx.crt \
    -p ${PORT}:443 -d nginx
echo "NGINX start check URL https://localhost:${PORT}"