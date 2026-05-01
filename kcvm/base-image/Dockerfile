# cvm-base — shared base for all CVM images
#
# Shared CVM base (systemd + kernel + kawa + verity + firewall)
#
# Auto-staged by cvmbuild before docker build:
#   kawa                     — binary at base-image/kawa, pinned by
#                              cvm.toml [image].kawa_version. Downloaded
#                              from KawiriAI/kawiri releases into
#                              /var/lib/kawiri/kawa/<ver>/, copied here.
#   dracut-modules/90verity-cvm/
#                            — cvmbuild's dm-verity dracut module.
#                              Shipped from cvmbuild's embedded assets,
#                              copied into /usr/lib/dracut/modules.d/
#                              by this Dockerfile.
#
# Reproducibility:
#   - Base image pinned by sha256 digest
#   - Apt mirror pinned to snapshot date
#   - kawa version pinned per image (every byte feeds SNP/TDX measurements)
#   - Initrd built by `dracut --reproducible` → deterministic by
#     construction (replaces our previous post-build CPIO byte-rewriter)

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
    # Initramfs (dracut produces deterministic initrds via --reproducible;
    # we no longer use initramfs-tools, which has open reproducibility
    # bugs around CPIO inode numbers and mtimes)
    dracut-core \
    # Common runtime libs
    procps \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

# --- Install kawa binary (pre-built) ---
COPY kawa /usr/local/bin/kawa
RUN chmod 755 /usr/local/bin/kawa

# --- dracut module for dm-verity root activation ---
# Staged by cvmbuild's stage_dracut_modules into base-image/dracut-modules/
# alongside the kawa binary above. The module's verity-root.sh runs at
# pre-mount inside the initrd, opens /dev/vda1 + /dev/vda2 via veritysetup,
# and exposes /dev/mapper/root for the kernel `root=` flow.
COPY dracut-modules/90verity-cvm/ /usr/lib/dracut/modules.d/90verity-cvm/
RUN chmod 755 /usr/lib/dracut/modules.d/90verity-cvm/*.sh \
    && KVER=$(ls /lib/modules) \
    && dracut \
        --reproducible \
        --force \
        --no-hostonly \
        --no-hostonly-cmdline \
        --strip \
        --add 'verity-cvm' \
        --omit 'lvm mdraid iscsi nfs cifs nbd plymouth network network-legacy network-manager dracut-network systemd-networkd resume bootchart fips selinux btrfs zfs dasd fcoe' \
        /boot/initrd.img-${KVER} ${KVER}

# --- Reproducibility: remove non-deterministic files ---
# Most of these are now redundant — cvmbuild's purge_build_logs handles
# them in the rootfs builder — but keeping them as defense in depth.
RUN echo "" > /etc/machine-id \
    && rm -f /var/cache/ldconfig/aux-cache \
    && rm -f /var/log/apt/history.log /var/log/apt/term.log /var/log/dpkg.log
