# kawiri-cvm — llama.cpp Q4 CPU inference image
#
# Requires: cvm-base:latest (built automatically by cvmbuild)
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

# --- Reproducibility purge (mirrors cvm-base) ---
# Wipe wallclock-tainted files left behind by this final stage's apt/dpkg activity.
RUN rm -f /var/lib/dbus/machine-id \
          /var/log/apt/history.log \
          /var/log/apt/term.log \
          /var/log/apt/eipp.log.xz \
          /var/log/dpkg.log \
          /var/log/alternatives.log \
          /var/log/bootstrap.log \
          /etc/ld.so.cache \
          /var/cache/ldconfig/aux-cache

# --- Restore stock apt config from the unmodified base image ---
# cvm-base set up snapshot-pinned sources for build; here we revert so the
# sealed rootfs has stock Ubuntu apt config (operator-independent, valid for
# post-build apt usage in non-CVM scenarios).
COPY --from=docker.io/library/ubuntu:26.04@sha256:5e275723f82c67e387ba9e3c24baa0abdcb268917f276a0561c97bef9450d0b4 /etc/apt/sources.list                  /etc/apt/sources.list
COPY --from=docker.io/library/ubuntu:26.04@sha256:5e275723f82c67e387ba9e3c24baa0abdcb268917f276a0561c97bef9450d0b4 /etc/apt/sources.list.d/ubuntu.sources /etc/apt/sources.list.d/ubuntu.sources
