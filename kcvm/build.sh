#!/usr/bin/env bash
# Convenience wrapper: bootstrap cvmbuild, then delegate.
# cvmbuild handles kawa/ovmf download (via /var/lib/kawiri cache), base-image
# build, per-image build, sealing, and measurement.
set -euo pipefail

cd "$(dirname "$0")/.."

CVMBUILD_VERSION="${CVMBUILD_VERSION:-v0.1.0}"
CVMBUILD_BIN="kcvm/bin/cvmbuild"

if [ ! -x "$CVMBUILD_BIN" ]; then
    mkdir -p kcvm/bin
    curl -fSL "https://github.com/KawiriAI/cvmbuild/releases/download/${CVMBUILD_VERSION}/cvmbuild-${CVMBUILD_VERSION}-linux-x86_64.tar.gz" \
        | tar -xz -C kcvm/bin/
    chmod +x "$CVMBUILD_BIN"
fi

if [ -z "${1:-}" ]; then
    echo "usage: $0 <image-id>" >&2
    echo "available:" >&2
    ls -1 kcvm/images/ >&2
    exit 1
fi

if [ ! -d "kcvm/images/$1" ]; then
    echo "error: image '$1' not found in kcvm/images/" >&2
    exit 1
fi

exec "$CVMBUILD_BIN" "kcvm/images/$1" build
