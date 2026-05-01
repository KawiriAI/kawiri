# cvm-base — shared base for all CVM images
#
# Shared CVM base (systemd + kernel + kawa + verity + firewall)
#
# Requires: pre-built kawa binary at kcvm/base-image/kawa
#   Build with: cd kawa && cargo build --release && cp target/release/kawa ../kcvm/base-image/
#   Or: ./kcvm/build.sh
#
# Reproducibility:
#   - Base image pinned by sha256 digest
#   - Apt mirror pinned to snapshot date

ARG UBUNTU_IMAGE=docker.io/library/ubuntu:26.04@sha256:5e275723f82c67e387ba9e3c24baa0abdcb268917f276a0561c97bef9450d0b4
ARG APT_MIRROR=http://snapshot.ubuntu.com
ARG APT_SNAPSHOT=20260426T000000Z
# Kernel ABI pinned literally (no HWE meta) so cvm-base and cvm-gpu-base
# stay in lockstep with linux-modules-nvidia-XXX-open-<ABI>-generic.
ARG KERNEL_ABI=7.0.0-14-generic

FROM ${UBUNTU_IMAGE} AS final

SHELL ["/bin/bash", "-c"]
ENV DEBIAN_FRONTEND=noninteractive

ARG APT_MIRROR
ARG APT_SNAPSHOT
ARG KERNEL_ABI
RUN rm -f /etc/apt/sources.list.d/*.sources /etc/apt/sources.list.d/*.list && \
    { echo "deb [check-date=no] ${APT_MIRROR}/ubuntu/${APT_SNAPSHOT} resolute main restricted universe multiverse"; \
      echo "deb [check-date=no] ${APT_MIRROR}/ubuntu/${APT_SNAPSHOT} resolute-updates main restricted universe multiverse"; \
      echo "deb [check-date=no] ${APT_MIRROR}/ubuntu/${APT_SNAPSHOT} resolute-security main restricted universe multiverse"; \
    } > /etc/apt/sources.list && \
    { echo 'Acquire::Check-Valid-Until "false";'; \
      echo 'Acquire::https::Verify-Peer "false";'; \
    } > /etc/apt/apt.conf.d/99snapshot

# Shared packages needed by ALL CVM images
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    # Core system
    systemd \
    udev \
    dbus \
    ca-certificates \
    ubuntu-keyring \
    # Kernel (literal ABI pin — keep in sync with cvm-gpu-base nvidia-open modules)
    linux-image-${KERNEL_ABI} \
    linux-modules-${KERNEL_ABI} \
    # Python (needed by verity-activate.py in all images)
    python3-minimal \
    # Crypto / verity
    cryptsetup-bin \
    kmod \
    zstd \
    # Networking / firewall
    nftables \
    systemd-timesyncd \
    # Initramfs
    initramfs-tools \
    # Common runtime libs
    procps \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

# --- Install kawa binary (pre-built) ---
COPY kawa /usr/local/bin/kawa
RUN chmod 755 /usr/local/bin/kawa

# --- verity-root initramfs hook ---
COPY <<'HOOK' /etc/initramfs-tools/hooks/verity-root
#!/bin/sh
set -e
. /usr/share/initramfs-tools/hook-functions
copy_exec /usr/sbin/veritysetup
manual_add_modules dm-mod dm-verity dm-bufio squashfs
HOOK
RUN chmod 755 /etc/initramfs-tools/hooks/verity-root \
    && update-initramfs -c -k all \
    && rm -f /boot/initrd.img.old

# --- Reproducibility: remove non-deterministic files ---
RUN echo "" > /etc/machine-id \
    && rm -f /boot/initrd.img.old \
    && rm -f /var/cache/ldconfig/aux-cache \
    && rm -f /var/log/apt/history.log /var/log/apt/term.log /var/log/dpkg.log
