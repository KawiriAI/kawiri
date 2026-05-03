# kawiri-cvm — vLLM GPU inference image (NVIDIA Confidential Computing)
#
# Requires: cvm-gpu-base:latest (built manually before cvmbuild)
#
# Why a separate Python 3.13:
#   cvm-gpu-base inherits cvm-base which is on Ubuntu 26.04 / resolute, where
#   the system Python is 3.14. vLLM 0.20.0 pulls in `cuda-tile==1.3.0` whose
#   PyPI wheels only support cp310-cp313 — no cp314 yet. We use `uv python
#   install 3.13` to drop a build-standalone CPython 3.13 into a venv, install
#   vLLM into that venv, and point the launcher at /opt/.venv/bin/python.
#   No apt, no PPA — uv downloads from python-build-standalone, all bytes
#   feed the rootfs hash like everything else.

ARG VLLM_VERSION=0.20.0
# Pin to a specific python-build-standalone descriptor rather than just `3.13`.
# uv resolves `3.13` to the latest patch at build time, which would drift the
# rootfs roothash on every cp313 patch release. The full descriptor identifies
# one specific tarball in github.com/astral-sh/python-build-standalone — once
# published, its bytes are immutable, so the rootfs stays stable until we
# deliberately bump this ARG.
ARG PYTHON_BUILD=cpython-3.13.12-linux-x86_64-gnu

# ============================================================
# Final CVM image
# ============================================================

FROM cvm-gpu-base:latest AS final

SHELL ["/bin/bash", "-c"]
ENV DEBIAN_FRONTEND=noninteractive

ARG VLLM_VERSION
ARG PYTHON_BUILD

# Runtime deps. python3-pip on the system Python only exists to bootstrap uv;
# the actual vLLM runtime uses /opt/.venv/bin/python (3.13 build-standalone).
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    python3-pip \
    libnuma1 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

# uv — Python installer + venv manager. Pinned to a version whose
# python-build-standalone catalog includes the PYTHON_BUILD descriptor
# above; bump in lockstep when bumping PYTHON_BUILD.
RUN pip3 install --no-cache-dir --break-system-packages uv==0.10.12

# Drop a build-standalone CPython 3.13 into a venv at /opt/.venv.
# uv expects the descriptor-pinned interpreter to be installed before `uv
# venv` references it (loose pins like `3.13` auto-download; full
# descriptors like cpython-3.13.X-linux-x86_64-gnu do not).
# Replace symlinks in the venv with a real binary copy so the rootfs is
# self-contained (no dangling links into /root/.local/share/uv/python).
RUN uv python install "${PYTHON_BUILD}" && \
    uv venv --python "${PYTHON_BUILD}" /opt/.venv && \
    REAL=$(readlink -f /opt/.venv/bin/python3) && \
    rm -f /opt/.venv/bin/python /opt/.venv/bin/python3 /opt/.venv/bin/python3.* && \
    cp "$REAL" /opt/.venv/bin/python3 && \
    ln -s python3 /opt/.venv/bin/python

ENV VIRTUAL_ENV=/opt/.venv
ENV PATH="/opt/.venv/bin:${PATH}"

# --- Install vLLM + torch (CUDA bundled via nvidia-* pip wheels) ---
# --torch-backend=cu126 forces the CUDA 12.6 variant of PyTorch (auto would
# pick CPU-only since Docker builds have no GPU). This pulls in nvidia-*
# pip wheels that bundle CUDA Runtime, cuBLAS, cuDNN, NCCL, etc.
RUN uv pip install --no-cache \
    "vllm==${VLLM_VERSION}" --torch-backend=cu126 && \
    rm -rf /root/.cache

# --- Register NVIDIA pip wheel libraries with ldconfig ---
# PyTorch/vLLM ship CUDA libs (libcudart, libcublas, libnccl, etc.) inside
# pip nvidia-* wheels under .venv/lib/python3.13/site-packages/nvidia/*/lib/.
# The dynamic linker doesn't search there by default, so we add them to
# ld.so.conf.
RUN find /opt/.venv -path '*/nvidia/*/lib' -type d | \
    sort -u > /etc/ld.so.conf.d/nvidia-pip.conf && \
    ldconfig

# --- vllm-launcher (uses /opt/.venv/bin/python directly) ---
COPY <<'LAUNCHER' /usr/local/bin/vllm-launcher
#!/opt/.venv/bin/python -I
"""Launch vLLM OpenAI-compatible API server with CVM-safe environment."""
import os, sys, time

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
