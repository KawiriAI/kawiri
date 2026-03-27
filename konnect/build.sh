#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

bun install --frozen-lockfile
bun run check
bun build core/mod.ts --outdir dist --target browser --format esm --sourcemap=external

echo "Built: dist/mod.js"
