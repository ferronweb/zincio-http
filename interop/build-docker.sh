#!/bin/bash
# This command build Docker images for the interop tests. The CLI arguments are appended to Docker build command
set -euo pipefail

clients_dir="$(dirname "$0")/clients"

client_build_base_commands=(
    "docker build --load -t zincio-http-interop-aioquic --target driver $clients_dir/aioquic"
    "docker build --load -t zincio-http-interop-curl --target driver $clients_dir/curl"
    "docker build --load -t zincio-http-interop-curl-http3 --target http3 $clients_dir/curl"
    "docker build --load -t zincio-http-interop-go --target driver $clients_dir/go"
    "docker build --load -t zincio-http-interop-neqo --target driver $clients_dir/neqo"
    "docker build --load -t zincio-http-interop-node --target driver $clients_dir/node"
    "docker build --load -t zincio-http-interop-okhttp --target driver $clients_dir/okhttp"
    "docker build --load -t zincio-http-interop-python-h2 --target driver $clients_dir/python-h2"
    "docker build --load -t zincio-http-interop-quic-go --target driver $clients_dir/quic-go"
    "docker build --load -t zincio-http-interop-quiche --target driver $clients_dir/quiche"
)

for build_base_command in "${client_build_base_commands[@]}"; do
    $build_base_command "$@"
done
