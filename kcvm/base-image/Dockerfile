# cvm-base — shared base for all CVM images
#
# Shared CVM base (systemd + kernel + kawa + verity + firewall)
#
# Auto-staged by cvmbuild before docker build:
#   kawa                     — binary at base-image/kawa, pinned by
#                              cvm.toml [image].kawa_version. Downloaded
#                              from KawiriAI/kawiri releases into
#                              /var/lib/kawiri/kawa/<ver>/, copied here.
#
# dm-verity root activation uses systemd's standard pipeline (no custom
# dracut module): apt brings in `systemd-cryptsetup` (provides
# /usr/lib/systemd/systemd-veritysetup + the cmdline generator) and
# `dmsetup` (provides 10-dm.rules + 60-persistent-storage-dm.rules,
# which release the libdevmapper udev cookie and emit SYSTEMD_READY=1
# so dev-mapper-root.device transitions to active). dracut's stock
# 11systemd-veritysetup + 70dm modules wire those together at initrd
# build time. The kernel cmdline carries
#   roothash=<hex>
#   systemd.verity_root_data=/dev/vda1
#   systemd.verity_root_hash=/dev/vda2
#   systemd.verity_root_options=panic-on-corruption
# and systemd-veritysetup-generator synthesizes systemd-veritysetup@root.service.
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
    # Crypto / verity. systemd-cryptsetup provides systemd-veritysetup
    # binary + system-generators/systemd-veritysetup-generator (without
    # which dracut's 11systemd-veritysetup module silently disables
    # itself). dmsetup ships the 10-dm.rules / 60-persistent-storage-dm
    # rules that release the libdevmapper udev cookie and mark dm
    # devices SYSTEMD_READY=1.
    cryptsetup-bin \
    systemd-cryptsetup \
    dmsetup \
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

# --- Build the initrd with dracut's stock systemd-veritysetup pipeline ---
# --add 'systemd-veritysetup' pulls in dracut's 11systemd-veritysetup
# (which depends on 70dm, so dm rules + dmsetup come along automatically).
# --add-drivers pins the kernel modules we always need: virtio block + net,
# squashfs (root fs type), and the dm-verity stack. dracut's --reproducible
# zeroes inode numbers and mtimes, so two cold builds of the same inputs
# produce identical initrds (every byte feeds SNP/TDX measurements).
RUN KVER=$(ls /lib/modules) \
    && dracut \
        --reproducible \
        --force \
        --no-hostonly \
        --no-hostonly-cmdline \
        --strip \
        --add 'systemd-veritysetup' \
        --add-drivers 'virtio_blk virtio_pci virtio_net squashfs dm-verity dm-bufio dm-mod' \
        --omit 'lvm mdraid iscsi nfs cifs nbd plymouth network network-legacy network-manager dracut-network systemd-networkd resume bootchart fips selinux btrfs zfs dasd fcoe' \
        /boot/initrd.img-${KVER} ${KVER}

# --- Reproducibility: remove non-deterministic files ---
# Most of these are now redundant — cvmbuild's purge_build_logs handles
# them in the rootfs builder — but keeping them as defense in depth.
RUN echo "" > /etc/machine-id \
    && rm -f /var/cache/ldconfig/aux-cache \
    && rm -f /var/log/apt/history.log /var/log/apt/term.log /var/log/dpkg.log
