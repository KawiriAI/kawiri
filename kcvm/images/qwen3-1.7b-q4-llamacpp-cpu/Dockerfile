# kawiri-cvm — Qwen3-1.7B llama.cpp Q4 CPU inference image
#
# Requires: cvm-base:latest (build with: just build-base)
#
# Stage 1: Build llama.cpp from source (C++, no Python)
# Stage 2: Final CVM image — cvm-base + llama-server
#
# Build context must be xcvm repo root.
#
# Reproducibility:
#   - Apt mirror pinned to snapshot date (inherited from cvm-base)
#   - llama.cpp pinned by git tag

ARG LLAMACPP_VERSION=b8470

# ============================================================
# Stage 1: Build llama.cpp from source
# ============================================================

FROM cvm-base:latest AS builder-llamacpp

SHELL ["/bin/bash", "-c"]
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc-13 g++-13 make cmake \
    curl ca-certificates \
    && update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-13 100 \
    && update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-13 100 \
    && ln -sf /usr/bin/gcc /usr/bin/cc \
    && ln -sf /usr/bin/g++ /usr/bin/c++ \
    && rm -rf /var/lib/apt/lists/*

ARG LLAMACPP_VERSION
WORKDIR /build
RUN curl -fsSL https://github.com/ggml-org/llama.cpp/archive/refs/tags/${LLAMACPP_VERSION}.tar.gz \
    | tar xz --strip-components=1

RUN cmake -B build \
    -DCMAKE_BUILD_TYPE=Release \
    -DGGML_NATIVE=ON \
    -DLLAMA_CURL=OFF \
    -DBUILD_SHARED_LIBS=OFF \
    && cmake --build build --target llama-server -j$(nproc) \
    && strip build/bin/llama-server

# ============================================================
# Stage 2: Final CVM image
# ============================================================

FROM cvm-base:latest AS final

SHELL ["/bin/bash", "-c"]
ENV DEBIAN_FRONTEND=noninteractive

# Image-specific packages (OpenMP runtime for llama-server)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libgomp1 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

# --- Install llama-server binary ---
COPY --from=builder-llamacpp /build/build/bin/llama-server /usr/local/bin/llama-server
RUN chmod 755 /usr/local/bin/llama-server
