#!/usr/bin/env bash
kubectl delete secret apache-ui || echo "Secrets apache-ui not found"
kubectl create secret tls apache-ui --cert=$(pwd)/scripts/config/apache-k8s/certs/server.crt --key=$(pwd)/scripts/config/apache-k8s/certs/server.key
rm -f $(pwd)/scripts/config/apache-k8s/certs/server.key