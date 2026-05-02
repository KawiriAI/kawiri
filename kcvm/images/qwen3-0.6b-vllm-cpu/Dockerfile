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
    torch==2.9.1+cpu --index-url https://download.pytorch.org/whl/cpu && \
    uv pip install --system --break-system-packages --no-cache \
    setuptools==82.0.0 \
    setuptools-scm==9.2.2 \
    wheel==0.46.1 \
    packaging==25.0 \
    ninja==1.13.0 \
    cmake==4.2.3 \
    numpy==2.4.2 \
    sentencepiece==0.2.1 \
    transformers==5.2.0 \
    pydantic==2.12.5 \
    pillow==12.1.1 \
    psutil==7.2.2 \
    py-cpuinfo==9.0.0

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
    torch==2.9.1+cpu --index-url https://download.pytorch.org/whl/cpu && \
    pip3 install --no-cache-dir --break-system-packages --no-deps /tmp/vllm-*.whl && \
    pip3 install --no-cache-dir --break-system-packages \
    --extra-index-url https://download.pytorch.org/whl/cpu \
    numpy sentencepiece transformers pydantic pillow psutil py-cpuinfo \
    tiktoken msgspec gguf compressed-tensors mistral-common \
    prometheus-client prometheus-fastapi-instrumentator \
    uvloop httptools fastapi uvicorn aiohttp \
    openai lm-format-enforcer partial-json-parser \
    depyf cloudpickle watchfiles python-json-logger ninja \
    pybase64 cbor2 ijson setproctitle numba \
    typing-extensions pyyaml tqdm protobuf requests filelock regex \
    tokenizers safetensors huggingface-hub jinja2 \
    model-hosting-container-standards pyzmq cachetools blake3 \
    diskcache einops lark opencv-python-headless six \
    outlines-core xgrammar grpcio mcp openai-harmony \
    llguidance anthropic && \
    rm -f /tmp/vllm-*.whl && \
    rm -rf /root/.cache/pip

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
