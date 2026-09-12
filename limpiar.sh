#!/usr/bin/env bash
# Borra contenedores, red y archivos generados del laboratorio.
set -uo pipefail
docker rm -f root unsigned alpha signed beta gamma delta test expired nods badalg recursive1 recursive2 2>/dev/null || true
docker network rm dnslab 2>/dev/null || true
sudo rm -rf "$(cd "$(dirname "$0")" && pwd)/lab" 2>/dev/null || true
echo "Laboratorio limpiado."
