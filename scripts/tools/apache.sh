#!/bin/bash
PORT=$1
cont=vault-apache

docker rm -f $cont || echo "Container $cont doesn't exists"
docker run --name $cont -v $(pwd)/scripts/config/nginx/nginx.conf:/etc/nginx/conf.d/default.conf:ro \
    -v $(pwd)/scripts/config/apache/certs:/opt/bitnami/apache/certs \
    -p ${PORT}:8443 -d  bitnami/apache:latest
echo "Apache start check URL https://localhost:${PORT}"