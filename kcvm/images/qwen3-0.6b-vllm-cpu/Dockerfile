# kawiri-cvm — vLLM CPU inference image
#
# Requires: cvm-base:latest (built automatically by cvmbuild)
#
# Stage 1: Build vLLM AVX2 CPU wheel from source
# Stage 2: Final CVM image — cvm-base + vLLM + Python deps
#
# Build context must be xcvm repo root.
#
# Reproducibility:
#   - Apt mirror pinned to snapshot date (inherited from cvm-base)
#   - vLLM built from pinned git tag

ARG VLLM_VERSION=0.20.0

# ============================================================
# Stage 1: Build vLLM AVX2 CPU wheel
# ============================================================

FROM cvm-base:latest AS builder-vllm

SHELL ["/bin/bash", "-c"]
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ make cmake ninja-build \
    python3 python3-dev python3-pip \
    curl git ca-certificates \
    libnuma-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# uv — fast Python package installer (pinned)
RUN pip install --no-cache-dir --break-system-packages uv==0.7.12

# Python build deps — all pinned
ENV UV_LINK_MODE=copy
RUN uv pip install --system --break-system-packages --no-cache \
    torch==2.11.0+cpu --index-url https://download.pytorch.org/whl/cpu && \
    uv pip install --system --break-system-packages --no-cache \
    setuptools==77.0.3 \
    setuptools-scm==10.0.5 \
    wheel==0.47.0 \
    packaging==26.2 \
    ninja==1.13.0 \
    cmake==4.3.2 \
    jinja2==3.1.6 \
    regex==2026.4.4 \
    numpy==2.4.4 \
    sentencepiece==0.2.1 \
    transformers==5.7.0 \
    pydantic==2.13.3 \
    pillow==12.2.0 \
    psutil==7.2.2 \
    py-cpuinfo==9.0.0 \
    numba==0.65.0 \
    intel-openmp==2024.2.1

ARG VLLM_VERSION
WORKDIR /vllm
RUN curl -fsSL https://github.com/vllm-project/vllm/archive/refs/tags/v${VLLM_VERSION}.tar.gz \
    | tar xz --strip-components=1

# setuptools-scm needs git metadata to infer version; tarballs don't have it
ARG VLLM_VERSION
ENV SETUPTOOLS_SCM_PRETEND_VERSION=${VLLM_VERSION}
ENV VLLM_TARGET_DEVICE=cpu
ENV VLLM_CPU_AVX2=1
ENV VLLM_CPU_DISABLE_AVX512=1
ENV MAX_JOBS=12
ENV SOURCE_DATE_EPOCH=1740009600

RUN set -o pipefail && \
    uv build --wheel --no-build-isolation -o /dist 2>&1 | tee /build.log

# Tag wheel as AVX2 variant
RUN cd /dist && \
    for f in vllm-*.whl; do \
        newname="$(echo "$f" | sed 's/+cpu/+cpu.avx2/')" && \
        [ "$f" != "$newname" ] && mv "$f" "$newname" || true; \
    done

# ============================================================
# Stage 2: Final CVM image
# ============================================================

FROM cvm-base:latest AS final

SHELL ["/bin/bash", "-c"]
ENV DEBIAN_FRONTEND=noninteractive

# Image-specific packages (vLLM runtime deps)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    python3-pip \
    libnuma1 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

# --- Install vLLM ---
COPY --from=builder-vllm /dist/vllm-*.whl /tmp/
RUN pip3 install --no-cache-dir --break-system-packages \
    torch==2.11.0+cpu --index-url https://download.pytorch.org/whl/cpu && \
    pip3 install --no-cache-dir --break-system-packages --no-deps /tmp/vllm-*.whl && \
    pip3 install --no-cache-dir --break-system-packages \
    --extra-index-url https://download.pytorch.org/whl/cpu \
    aiohttp==3.13.5 \
    anthropic==0.97.0 \
    blake3==1.0.8 \
    cachetools==7.1.0 \
    cbor2==6.0.1 \
    cloudpickle==3.1.2 \
    compressed-tensors==0.15.0.1 \
    depyf==0.20.0 \
    diskcache==5.6.3 \
    einops==0.8.2 \
    fastapi==0.136.1 \
    filelock==3.29.0 \
    gguf==0.18.0 \
    grpcio==1.80.0 \
    httptools==0.7.1 \
    huggingface-hub==1.13.0 \
    ijson==3.5.0 \
    intel-openmp==2024.2.1 \
    jinja2==3.1.6 \
    lark==1.2.2 \
    llguidance==1.3.0 \
    lm-format-enforcer==0.11.3 \
    mcp==1.27.0 \
    "mistral-common[image]==1.11.1" \
    model-hosting-container-standards==0.1.14 \
    msgspec==0.21.1 \
    ninja==1.13.0 \
    numba==0.65.0 \
    numpy==2.4.4 \
    openai==2.33.0 \
    openai-harmony==0.0.8 \
    opencv-python-headless==4.13.0.92 \
    outlines-core==0.2.14 \
    partial-json-parser==0.2.1.1.post7 \
    pillow==12.2.0 \
    prometheus-client==0.25.0 \
    prometheus-fastapi-instrumentator==7.1.0 \
    protobuf==7.34.1 \
    psutil==7.2.2 \
    py-cpuinfo==9.0.0 \
    pybase64==1.4.3 \
    pydantic==2.13.3 \
    python-json-logger==4.1.0 \
    pyyaml==6.0.3 \
    pyzmq==27.1.0 \
    regex==2026.4.4 \
    requests==2.33.1 \
    safetensors==0.7.0 \
    sentencepiece==0.2.1 \
    setproctitle==1.3.7 \
    six==1.17.0 \
    tiktoken==0.12.0 \
    tokenizers==0.22.2 \
    tqdm==4.67.3 \
    transformers==5.7.0 \
    typing-extensions==4.15.0 \
    uvicorn==0.46.0 \
    uvloop==0.22.1 \
    watchfiles==1.1.1 \
    xgrammar==0.2.0 \
    && rm -f /tmp/vllm-*.whl \
    && rm -rf /root/.cache/pip

# --- vllm-launcher (shell-free, env -i for CVM isolation) ---
COPY <<'LAUNCHER' /usr/local/bin/vllm-launcher
#!/usr/bin/python3 -I
"""Launch vLLM OpenAI-compatible API server with CVM-safe environment."""
import os, sys

# Force CPU platform detection (vLLM checks version string for +cpu)
os.environ.setdefault("VLLM_TARGET_DEVICE", "cpu")

# Writable home for vLLM cache (model registry, etc.)
os.environ.setdefault("HOME", "/run/vllm")
os.makedirs("/run/vllm/.cache", exist_ok=True)

# Read config from environment
model = os.environ.get("VLLM_MODEL", "")
if not model:
    print("FATAL: VLLM_MODEL not set", file=sys.stderr)
    sys.exit(1)

args = [
    sys.executable, "-I", "-m", "vllm.entrypoints.openai.api_server",
    "--model", model,
    "--host", "127.0.0.1",
    "--port", os.environ.get("VLLM_PORT", "8000"),
    "--served-model-name", os.environ.get("VLLM_SERVED_MODEL_NAME", model),
    "--max-model-len", os.environ.get("VLLM_MAX_MODEL_LEN", "2048"),
    "--max-num-seqs", os.environ.get("VLLM_MAX_NUM_SEQS", "4"),
]

os.execv(sys.executable, args)
LAUNCHER
RUN chmod 755 /usr/local/bin/vllm-launcher

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
