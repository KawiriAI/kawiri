# kawiri-cvm — SGLang CPU inference image
#
# Requires: cvm-base:latest (built automatically by cvmbuild)
#
# Stage 1: Build SGLang CPU backend from source
# Stage 2: Final CVM image — cvm-base + SGLang venv + runtime libs
#
# Build context must be xcvm repo root.
#
# Reproducibility:
#   - Apt mirror pinned to snapshot date (inherited from cvm-base)
#   - SGLang pinned by git tag

ARG SGLANG_VERSION=v0.5.10.post1

# ============================================================
# Stage 1: Build SGLang CPU backend
# ============================================================

FROM cvm-base:latest AS builder-sglang

SHELL ["/bin/bash", "-c"]
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc-13 g++-13 make cmake \
    python3 python3-dev python3-pip python3-venv \
    curl ca-certificates \
    libnuma-dev libssl-dev libsqlite3-dev \
    libgoogle-perftools-dev libtbb-dev \
    && update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-13 100 \
    && update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-13 100 \
    && ln -sf /usr/bin/gcc /usr/bin/cc \
    && ln -sf /usr/bin/g++ /usr/bin/c++ \
    && rm -rf /var/lib/apt/lists/*

# uv for fast installs
RUN pip install --no-cache-dir --break-system-packages uv==0.7.12

WORKDIR /opt
# Use system Python so the venv is compatible with the final stage (the
# venv copies binaries from this builder into /opt/.venv on the final
# image — they must match the final image's Python ABI). Replace symlinks
# with a real copy of the python binary so that when the venv is copied
# to the final stage, Python's sys.executable resolves to
# /opt/.venv/bin/python3 and pyvenv.cfg is found for site-packages discovery.
RUN uv venv --python python3 && \
    REAL=$(readlink -f /opt/.venv/bin/python3) && \
    rm -f /opt/.venv/bin/python /opt/.venv/bin/python3 /opt/.venv/bin/python3.* && \
    cp "$REAL" /opt/.venv/bin/python3 && \
    ln -s python3 /opt/.venv/bin/python

# Configure PyTorch CPU index
RUN echo -e '[[index]]\nname = "torch"\nurl = "https://download.pytorch.org/whl/cpu"\n\n[[index]]\nname = "torchvision"\nurl = "https://download.pytorch.org/whl/cpu"\n\n[[index]]\nname = "torchaudio"\nurl = "https://download.pytorch.org/whl/cpu"\n\n[[index]]\nname = "triton"\nurl = "https://download.pytorch.org/whl/cpu"' > .venv/uv.toml

ENV UV_CONFIG_FILE=/opt/.venv/uv.toml

ARG SGLANG_VERSION
WORKDIR /build/sglang
RUN curl -fsSL https://github.com/sgl-project/sglang/archive/refs/tags/${SGLANG_VERSION}.tar.gz \
    | tar xz --strip-components=1
ENV CC=gcc CXX=g++
# setuptools-scm needs git metadata to infer version; tarballs don't have it
# setuptools-scm reads the package version from git metadata; tarballs don't
# have it. Strip the leading 'v' from SGLANG_VERSION (v0.5.10.post1 → 0.5.10.post1).
ENV SETUPTOOLS_SCM_PRETEND_VERSION=${SGLANG_VERSION#v}
RUN source /opt/.venv/bin/activate && \
    cd python && \
    cp pyproject_cpu.toml pyproject.toml && \
    uv pip install . && \
    cd ../sgl-kernel && \
    cp pyproject_cpu.toml pyproject.toml && \
    uv pip install .

# ============================================================
# Stage 2: Final CVM image
# ============================================================

FROM cvm-base:latest AS final

SHELL ["/bin/bash", "-c"]
ENV DEBIAN_FRONTEND=noninteractive

# Image-specific packages (SGLang runtime deps)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    python3 \
    libnuma1 \
    libgoogle-perftools4t64 \
    libtbbmalloc2 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

# --- Install SGLang virtualenv ---
COPY --from=builder-sglang /opt/.venv /opt/.venv
RUN find /opt/.venv -type d -exec chmod 755 {} + && \
    find /opt/.venv -type f -exec chmod a+r {} + && \
    find /opt/.venv/bin -type f -exec chmod 755 {} + && \
    test -f /opt/.venv/bin/python3 && test -x /opt/.venv/bin/python3 && \
    echo "venv python3 OK: $(/opt/.venv/bin/python3 --version)"

# --- sglang-launcher (shell-free, uses venv python directly) ---
COPY <<'LAUNCHER' /usr/local/bin/sglang-launcher
#!/opt/.venv/bin/python3
"""Launch SGLang OpenAI-compatible API server with CVM-safe environment."""
import os, sys

os.environ.setdefault("SGLANG_USE_CPU_ENGINE", "1")

model = os.environ.get("SGLANG_MODEL", "")
if not model:
    print("FATAL: SGLANG_MODEL not set", file=sys.stderr)
    sys.exit(1)

sys.argv = [
    "sglang-launcher",
    "--model-path", model,
    "--host", "127.0.0.1",
    "--port", os.environ.get("SGLANG_PORT", "30000"),
    "--served-model-name", os.environ.get("SGLANG_SERVED_MODEL_NAME", model),
    "--max-total-tokens", os.environ.get("SGLANG_MAX_MODEL_LEN", "2048"),
    "--disable-overlap-schedule",
    "--device", "cpu",
    "--tp", "1",
]

from runpy import run_module
run_module("sglang.launch_server", run_name="__main__", alter_sys=True)
LAUNCHER
RUN chmod 755 /usr/local/bin/sglang-launcher
