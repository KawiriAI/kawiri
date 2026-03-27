#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

mkdir -p out

docker buildx build -f Dockerfile.ovmf -o out/ .

echo "Built:"
ls -la out/
