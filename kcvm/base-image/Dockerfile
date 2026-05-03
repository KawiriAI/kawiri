# cvm-base — shared base for all CVM images
#
# Self-contained Dockerfile: cvmbuild does NOT stage anything into this build
# context. The contract is:
#   - Pass APT_MIRROR / APT_SNAPSHOT / KAWA_VERSION via
#     `docker build --build-arg`, or use the defaults baked here.
#   - cvmbuild's role is to invoke `docker buildx build`, extract, package,
#     and measure — it does not modify Dockerfiles or stage binaries.
#
# kawa is shipped as a single binary that auto-detects whether the kernel
# offers a usable configfs-tsm TSM provider at boot. Real TEE hardware →
# signed quotes; non-TEE → loud per-message mock-attestation warnings.
# There is no `KAWA_VARIANT` build-arg anymore — one binary, one image.
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
#   - kawa version pinned by build-arg (every byte feeds SNP/TDX measurements)
#   - Initrd built by `dracut --reproducible` → deterministic by
#     construction (replaces our previous post-build CPIO byte-rewriter)

ARG UBUNTU_IMAGE=docker.io/library/ubuntu:26.04@sha256:5e275723f82c67e387ba9e3c24baa0abdcb268917f276a0561c97bef9450d0b4
ARG APT_SNAPSHOT=20260501T000000Z
ARG APT_MIRROR=http://snapshot.ubuntu.com
# Kernel ABI pinned literally (no HWE meta) so cvm-base and cvm-gpu-base
# stay in lockstep with linux-modules-nvidia-XXX-open-<ABI>-generic.
ARG KERNEL_ABI=7.0.0-14-generic
# kawa pin — one binary that runtime-detects TEE backing.
ARG KAWA_VERSION=0.1.2

FROM ${UBUNTU_IMAGE} AS final

SHELL ["/bin/bash", "-c"]
ENV DEBIAN_FRONTEND=noninteractive

ARG APT_SNAPSHOT
ARG APT_MIRROR
ARG KERNEL_ABI
ARG KAWA_VERSION

# Apt mirror via build-arg (not secret): the URL becomes part of the layer
# fingerprint, but as long as APT_MIRROR is stable across runs (either the
# default snapshot.ubuntu.com, or cvmbuild-aptcache running on a fixed port)
# the cache stays warm. Random-port aptcache is a knowing trade-off the
# operator opts into.
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
    # Needed for the kawa fetch below — removed from the rootfs by cvmbuild
    # via security.remove if listed.
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

# --- Fetch kawa binary from the kawiri release that matches KAWA_VERSION ---
# Single binary, no variant: kawa runtime-detects whether configfs-tsm offers
# a real TSM provider at startup and picks attestation mode accordingly.
# Production deployments rely on konnect's KattValidator rejecting any payload
# with platform=="mock" (its default).
RUN set -euo pipefail \
    && url="https://github.com/KawiriAI/kawiri/releases/download/kawa-v${KAWA_VERSION}/kawa-v${KAWA_VERSION}-linux-x86_64.tar.gz" \
    && echo "fetching ${url}" \
    && curl -fsSL "${url}" -o /tmp/kawa.tar.gz \
    && mkdir -p /tmp/kawa-extract \
    && tar -xzf /tmp/kawa.tar.gz -C /tmp/kawa-extract \
    && bin=$(find /tmp/kawa-extract -maxdepth 2 -name 'kawa-bin' -o -name 'kawa' | head -n1) \
    && test -n "${bin}" \
    && install -m 0755 "${bin}" /usr/local/bin/kawa \
    && rm -rf /tmp/kawa.tar.gz /tmp/kawa-extract

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

# --- Reproducibility purge ---
# These files contain wallclock timestamps from the docker build OR are
# recreated at boot. Two cold builds without this step produce different
# rootfs roothashes purely from apt/dpkg log timing skew.
#   /etc/machine-id, /var/lib/dbus/machine-id  recreated by systemd at boot
#   /var/log/{apt/*,dpkg.log,alternatives.log,bootstrap.log}  build-time logs
#   /etc/ld.so.cache, /var/cache/ldconfig/aux-cache  regenerated on demand
# /etc/apt/sources.list is left intact so child Dockerfiles can run apt
# without re-stamping; it's deterministic from APT_MIRROR + APT_SNAPSHOT
# and apt itself is removed from the runtime rootfs via security.remove.
RUN echo "" > /etc/machine-id \
    && rm -f /var/lib/dbus/machine-id \
             /var/log/apt/history.log \
             /var/log/apt/term.log \
             /var/log/apt/eipp.log.xz \
             /var/log/dpkg.log \
             /var/log/alternatives.log \
             /var/log/bootstrap.log \
             /etc/ld.so.cache \
             /var/cache/ldconfig/aux-cache
