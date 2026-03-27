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

ARG UBUNTU_IMAGE=docker.io/library/ubuntu:24.04@sha256:67efaecc0031a612cf7bb3c863407018dbbef0a971f62032b77aa542ac8ac0d2
ARG APT_MIRROR=http://snapshot.ubuntu.com
ARG APT_SNAPSHOT=20260320T000000Z

FROM ${UBUNTU_IMAGE} AS final

SHELL ["/bin/bash", "-c"]
ENV DEBIAN_FRONTEND=noninteractive

ARG APT_MIRROR
ARG APT_SNAPSHOT
RUN rm -f /etc/apt/sources.list.d/*.sources /etc/apt/sources.list.d/*.list && \
    { echo "deb [check-date=no] ${APT_MIRROR}/ubuntu/${APT_SNAPSHOT} noble main restricted universe multiverse"; \
      echo "deb [check-date=no] ${APT_MIRROR}/ubuntu/${APT_SNAPSHOT} noble-updates main restricted universe multiverse"; \
      echo "deb [check-date=no] ${APT_MIRROR}/ubuntu/${APT_SNAPSHOT} noble-security main restricted universe multiverse"; \
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
    # Kernel
    linux-generic-hwe-24.04 \
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
