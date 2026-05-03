# ubuntu-26.04-ssh-cvm — attestation-gated SSH-able CVM
#
# This is NOT an inference image. There's no kawa upstream — kawa runs in
# standalone+tunnel mode, accepting only `tunnel.open port=22` and relaying
# bytes to a loopback sshd. Operators who SSH in get a normal Ubuntu shell
# inside a confidential VM with read-only verity rootfs.
#
# Requires cvm-base:latest (kawa, kernel, dracut, systemd, dm-verity stack).

FROM cvm-base:latest

SHELL ["/bin/bash", "-c"]
ENV DEBIAN_FRONTEND=noninteractive

# Re-populate apt lists (cvm-base wipes /var/lib/apt/lists/*) and install
# the SSH server. vim-tiny + less + iputils-ping for basic interactive
# usability — without them an SSH'd-in operator is squinting at `cat` and
# would have no way to debug network issues.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        vim-tiny \
        less \
        iputils-ping \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

# Disable Ubuntu's stock ssh socket activation — we run sshd directly via
# our own systemd unit (declared in cvm.toml [services.units]) so the host
# keys can be generated into a tmpfs at boot before sshd starts.
RUN systemctl disable ssh.socket ssh.service 2>/dev/null || true \
    && rm -f /etc/ssh/sshd_config.d/*.conf

# Ubuntu's base image ships root with shell=/usr/sbin/nologin. sshd will
# happily accept pubkey auth and then exec nologin, which prints "This
# account is currently not available" and exits. Give root /bin/bash so
# the SSH session actually drops into a shell.
RUN sed -i 's,^root:x:0:0:root:/root:/usr/sbin/nologin$,root:x:0:0:root:/root:/bin/bash,' /etc/passwd

# Bake the overlay tree directly into the rootfs via Docker COPY rather
# than cvmbuild's [overlay.files] mechanism — cvmbuild resolves overlay
# src paths relative to its CWD (teehost's working dir), so the explicit
# Docker COPY from the build context is the bulletproof option. The
# build context is the kcvm/ repo root (cvm.toml's `context = "../..").
COPY images/ubuntu-26.04-ssh-cvm/overlay/root/.ssh/authorized_keys /root/.ssh/authorized_keys
COPY images/ubuntu-26.04-ssh-cvm/overlay/usr/local/sbin/sshd-keygen /usr/local/sbin/sshd-keygen

# Lock down perms (Docker COPY preserves source mode; redo here to be
# explicit and resistant to host umask quirks).
RUN chmod 700 /root/.ssh \
    && chmod 600 /root/.ssh/authorized_keys \
    && chmod 755 /usr/local/sbin/sshd-keygen

# /home is empty by design — anything written there is on the read-only
# rootfs. Operators wanting persistent state should add a [[verity_disks]]
# entry in their fork's cvm.toml; this test image is ephemeral.
