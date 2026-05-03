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

# Pre-create /run/sshd-keys mount target (sshd-keygen.service writes here).
# /run is tmpfs at boot so this is just the directory entry on the rootfs.
RUN mkdir -p /run/sshd-keys && chmod 700 /run/sshd-keys

# Pre-create /run/sshd PID-file dir for sshd's privsep (a stock Ubuntu
# requirement; sshd refuses to start if it can't chdir there).
RUN mkdir -p /run/sshd && chmod 755 /run/sshd

# /root/.ssh is on the read-only rootfs (verity); the overlay/ tree provides
# the authorized_keys file directly so no boot-time write is needed.
RUN mkdir -p /root/.ssh && chmod 700 /root/.ssh

# /home is empty by design — anything written there is on the read-only
# rootfs. Operators wanting persistent state should add a [[verity_disks]]
# entry in their fork's cvm.toml; this test image is ephemeral.
