# kawiri-cvm — llama.cpp Q4 GPU inference image (NVIDIA Confidential Computing)
#
# Requires: cvm-gpu-base:latest (built automatically by cvmbuild)
#
# Stage 1: Build llama.cpp with CUDA support
# Stage 2: Final CVM image — cvm-gpu-base + CUDA libs + llama-server
#
# Build context must be xcvm repo root.
#
# CUDA toolkit is only needed at build time — llama-server links statically.

ARG LLAMACPP_VERSION=b8470
ARG CUDA_VERSION=12-6

# ============================================================
# Stage 1: Build llama.cpp with CUDA
# ============================================================

FROM docker.io/nvidia/cuda:13.2.0-devel-ubuntu24.04 AS builder-llamacpp

ENV DEBIAN_FRONTEND=noninteractive
ARG APT_MIRROR=http://snapshot.ubuntu.com
ARG APT_SNAPSHOT=20260320T000000Z
RUN rm -f /etc/apt/sources.list.d/*.sources /etc/apt/sources.list.d/*.list && \
    { echo "deb [check-date=no] ${APT_MIRROR}/ubuntu/${APT_SNAPSHOT} noble main restricted universe multiverse"; \
      echo "deb [check-date=no] ${APT_MIRROR}/ubuntu/${APT_SNAPSHOT} noble-updates main restricted universe multiverse"; \
      echo "deb [check-date=no] ${APT_MIRROR}/ubuntu/${APT_SNAPSHOT} noble-security main restricted universe multiverse"; \
    } > /etc/apt/sources.list && \
    { echo 'Acquire::Check-Valid-Until "false";'; \
      echo 'Acquire::https::Verify-Peer "false";'; \
    } > /etc/apt/apt.conf.d/99snapshot

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc-14 g++-14 make cmake curl ca-certificates \
    && update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-14 100 \
    && update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-14 100 \
    && ln -sf /usr/bin/gcc /usr/bin/cc \
    && ln -sf /usr/bin/g++ /usr/bin/c++ \
    && rm -rf /var/lib/apt/lists/*

ARG LLAMACPP_VERSION
WORKDIR /build
RUN curl -fsSL https://github.com/ggml-org/llama.cpp/archive/refs/tags/${LLAMACPP_VERSION}.tar.gz \
    | tar xz --strip-components=1

RUN cmake -B build \
    -DCMAKE_BUILD_TYPE=Release \
    -DGGML_NATIVE=OFF \
    -DGGML_CUDA=ON \
    -DCMAKE_CUDA_ARCHITECTURES="90;100;120" \
    -DLLAMA_CURL=OFF \
    -DBUILD_SHARED_LIBS=OFF \
    && cmake --build build --target llama-server -j$(nproc) \
    && strip build/bin/llama-server

# ============================================================
# Stage 2: Final CVM image
# ============================================================

FROM cvm-gpu-base:latest AS final

SHELL ["/bin/bash", "-c"]
ENV DEBIAN_FRONTEND=noninteractive

# Runtime deps (OpenMP for llama-server)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libgomp1 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

# --- Install llama-server binary (CUDA-linked) ---
COPY --from=builder-llamacpp /build/build/bin/llama-server /usr/local/bin/llama-server
RUN chmod 755 /usr/local/bin/llama-server

# --- Copy CUDA runtime libs needed by llama-server ---
COPY --from=builder-llamacpp /usr/local/cuda/lib64/libcudart.so* /usr/local/lib/
COPY --from=builder-llamacpp /usr/local/cuda/lib64/libcublas.so* /usr/local/lib/
COPY --from=builder-llamacpp /usr/local/cuda/lib64/libcublasLt.so* /usr/local/lib/
RUN ldconfig
