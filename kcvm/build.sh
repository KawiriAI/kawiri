#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

CVMBUILD_VERSION="${CVMBUILD_VERSION:-v0.1.0}"
CVMBUILD_URL="https://github.com/KawiriAI/cvmbuild/releases/download/${CVMBUILD_VERSION}/cvmbuild-${CVMBUILD_VERSION}-linux-x86_64.tar.gz"
CVMBUILD_BIN="kcvm/bin/cvmbuild"

# Download cvmbuild if not present
if [ ! -x "$CVMBUILD_BIN" ]; then
    echo "Downloading cvmbuild ${CVMBUILD_VERSION}..."
    mkdir -p kcvm/bin
    curl -fSL "$CVMBUILD_URL" | tar -xz -C kcvm/bin/
    chmod +x "$CVMBUILD_BIN"
fi

# Build kawa if not already built
if [ ! -f kawa/target/release/kawa ]; then
    echo "Building kawa..."
    ./kawa/build.sh
fi

# Copy kawa binary into base-image build context
cp kawa/target/release/kawa kcvm/base-image/kawa

# Build base image
docker buildx build \
    --network=host \
    -t cvm-base:latest \
    -f kcvm/base-image/Dockerfile \
    kcvm/base-image/

echo "Base image tagged: cvm-base:latest"

# Build a specific image if provided
if [ -n "${1:-}" ]; then
    image="$1"
    if [ ! -d "kcvm/images/$image" ]; then
        echo "error: image '$image' not found" >&2
        echo "available:" >&2
        ls -1 kcvm/images/ >&2
        exit 1
    fi
    docker buildx build \
        --network=host \
        -t "cvm-$image:latest" \
        -f "kcvm/images/$image/Dockerfile" \
        "kcvm/images/$image/"
    echo "Image tagged: cvm-$image:latest"
fi
