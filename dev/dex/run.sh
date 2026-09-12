#!/bin/sh
# Start (or restart) the local Dex OP in podman. Idempotent.
set -eu
dir=$(cd "$(dirname "$0")" && pwd)

podman machine start >/dev/null 2>&1 || true
podman rm -f dex >/dev/null 2>&1 || true

podman run -d --name dex \
  -p 127.0.0.1:5556:5556 \
  -v "$dir/config.yaml:/etc/dex/config.yaml:ro" \
  ghcr.io/dexidp/dex:latest \
  dex serve /etc/dex/config.yaml

echo "dex up: http://localhost:5556/dex/.well-known/openid-configuration"
