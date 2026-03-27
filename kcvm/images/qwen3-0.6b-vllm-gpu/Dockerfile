# kawiri-cvm — vLLM GPU inference image (NVIDIA Confidential Computing)
#
# Requires: cvm-gpu-base:latest (build with: just build-gpu-base)
#
# Build context must be xcvm repo root.
#
# vLLM 0.17.0+ bundles CUDA libraries via pip nvidia-* wheels,
# so we only need the NVIDIA userspace driver — no CUDA apt repo needed.

ARG VLLM_VERSION=0.18.0

# ============================================================
# Final CVM image
# ============================================================

FROM cvm-gpu-base:latest AS final

SHELL ["/bin/bash", "-c"]
ENV DEBIAN_FRONTEND=noninteractive

ARG VLLM_VERSION

# Runtime deps
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    python3-pip \
    libnuma1 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

# --- Install uv (fast Python package installer) ---
RUN pip3 install --no-cache-dir --break-system-packages uv==0.7.12

# --- Install vLLM + torch (CUDA bundled via nvidia-* pip wheels) ---
# --torch-backend=cu126 forces the CUDA 12.6 variant of PyTorch (auto would
# pick CPU-only since Docker builds have no GPU). This pulls in nvidia-*
# pip wheels that bundle CUDA Runtime, cuBLAS, cuDNN, NCCL, etc.
RUN uv pip install --system --break-system-packages --no-cache \
    "vllm==${VLLM_VERSION}" --torch-backend=cu126 && \
    rm -rf /root/.cache

# --- Register NVIDIA pip wheel libraries with ldconfig ---
# PyTorch/vLLM ship CUDA libs (libcudart, libcublas, libnccl, etc.) inside
# pip nvidia-* wheels under site-packages/nvidia/*/lib/. The dynamic linker
# doesn't search there by default, so we add them to ld.so.conf.
RUN find /usr/local/lib -path '*/nvidia/*/lib' -type d | \
    sort -u > /etc/ld.so.conf.d/nvidia-pip.conf && \
    ldconfig

# --- vllm-launcher (shell-free, env -i for CVM isolation) ---
COPY <<'LAUNCHER' /usr/local/bin/vllm-launcher
#!/usr/bin/python3 -I
"""Launch vLLM OpenAI-compatible API server with CVM-safe environment."""
import os, sys, subprocess, time

def log(msg):
    print(msg, flush=True)

# Writable home for vLLM cache (model registry, etc.)
os.environ.setdefault("HOME", "/run/vllm")
os.makedirs("/run/vllm/.cache", exist_ok=True)

# Wait for CUDA to be available (CC ready state set by nvidia-uvm-load.service as root)
import ctypes
for attempt in range(60):
    try:
        cuda = ctypes.CDLL("libcuda.so.1")
        r = cuda.cuInit(0)
        if r == 0:
            count = ctypes.c_int(0)
            cuda.cuDeviceGetCount(ctypes.byref(count))
            log(f"CUDA ready: {count.value} device(s) (attempt {attempt + 1})")
            break
        log(f"cuInit returned {r}, retrying... (attempt {attempt + 1}/60)")
    except Exception as e:
        log(f"CUDA check error: {e}")
    time.sleep(2)
else:
    log("FATAL: CUDA not available after 120s")
    sys.exit(1)

# Read config from environment
model = os.environ.get("VLLM_MODEL", "")
if not model:
    log("FATAL: VLLM_MODEL not set")
    sys.exit(1)

args = [
    sys.executable, "-I", "-m", "vllm.entrypoints.openai.api_server",
    "--model", model,
    "--host", "127.0.0.1",
    "--port", os.environ.get("VLLM_PORT", "8000"),
    "--served-model-name", os.environ.get("VLLM_SERVED_MODEL_NAME", model),
    "--max-model-len", os.environ.get("VLLM_MAX_MODEL_LEN", "2048"),
    "--max-num-seqs", os.environ.get("VLLM_MAX_NUM_SEQS", "4"),
    "--tensor-parallel-size", os.environ.get("VLLM_TP_SIZE", "1"),
    "--gpu-memory-utilization", os.environ.get("VLLM_GPU_MEM_UTIL", "0.90"),
]

# Optional: enforce eager mode (no CUDA graph) for CC mode
if os.environ.get("VLLM_ENFORCE_EAGER", "").lower() in ("1", "true"):
    args.append("--enforce-eager")

os.execv(sys.executable, args)
LAUNCHER
RUN chmod 755 /usr/local/bin/vllm-launcher
