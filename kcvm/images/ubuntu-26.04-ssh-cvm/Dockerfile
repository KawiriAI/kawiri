# ubuntu-26.04-ssh-cvm — confidential VM with direct SSH
#
# This is NOT an inference image and doesn't run kawa. sshd binds 0.0.0.0:22
# (declared in cvm.toml [network].expose_port) and operators connect with
# stock SSH. Attestation is verified post-login by the operator reading
# /sys/kernel/config/tsm/report directly inside the CVM.
#
# Requires cvm-base:latest (kernel, dracut, systemd, dm-verity stack — the
# kawa binary it ships is unused here, dead weight that costs ~5 MB).

FROM cvm-base:latest

SHELL ["/bin/bash", "-c"]
ENV DEBIAN_FRONTEND=noninteractive

# Re-populate apt lists (cvm-base wipes /var/lib/apt/lists/*) and install
# the SSH server, basic interactive tooling, and Docker.
#
# docker.io is Ubuntu's stock Docker package — pulls in containerd, runc,
# iptables, bridge-utils, and (importantly for us) creates the `docker`
# group via the package post-install. Operators logging in as root are
# implicitly able to talk to /var/run/docker.sock; on a fork that adds a
# non-root user, that user gets Docker access by `usermod -aG docker <name>`.
#
# Caveats this image inherits from the cvmbuild platform:
#   - `outbound = "deny"` (cvmbuild rejects any other value at validate
#     time as a zero-trust violation), so `docker pull` from the public
#     internet won't work out of the box. Operators wanting external pulls
#     either bake images at build time (additional layers below this point),
#     `docker load` from a tarball SCP'd in over SSH, or — since they're
#     root in the VM — `nft flush ruleset` to relax the policy. See README.
#   - `lock_modules = true` + lockdown=confidentiality means Docker can't
#     modprobe at runtime; the kernel modules it needs are loaded via
#     [kernel].initrd_modules in cvm.toml.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        vim-tiny \
        less \
        iputils-ping \
        docker.io \
        cryptsetup \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

# `apt install docker.io` does create the `docker` group via post-install,
# but only when Debian's adduser scripts run cleanly under buildkit. The
# explicit `groupadd -r` is the defensive belt-and-suspenders so a fork
# can `usermod -aG docker <newuser>` without surprise.
RUN groupadd -r -f docker

# Enable Docker's units the standard apt-shipped way: dpkg dropped the
# unit files into /lib/systemd/system; we just create the multi-user
# wants symlinks so systemd starts them at boot. (Inside Docker build
# context `systemctl enable` is a pure filesystem op — it just makes
# the symlinks — so this works without a running systemd.)
RUN systemctl enable docker.socket docker.service containerd.service

# Disable Ubuntu's stock ssh socket activation — we run sshd directly via
# our own systemd unit (declared in cvm.toml [services.units]) so the host
# keys can be generated into a tmpfs at boot before sshd starts.
RUN systemctl disable ssh.socket ssh.service 2>/dev/null || true \
    && rm -f /etc/ssh/sshd_config.d/*.conf

# cvmbuild's hardening pass unconditionally rewrites every login shell in
# /etc/passwd to /usr/sbin/nologin (good for chat-only CVMs, fatal for an
# SSH-CVM). To work around it without forking cvmbuild, we bake a side-by-
# side passwd file with root's shell set to /bin/bash at a path cvmbuild
# leaves alone, and BindReadOnlyPaths it onto /etc/passwd inside the sshd
# unit's mount namespace at runtime (see cvm.toml). The system-wide
# /etc/passwd still has root=nologin so no other service is surprised.
RUN sed 's,^root:x:0:0:root:/root:/usr/sbin/nologin$,root:x:0:0:root:/root:/bin/bash,' /etc/passwd > /etc/passwd.sshd \
    && chmod 644 /etc/passwd.sshd

# Bake the overlay tree directly into the rootfs via Docker COPY rather
# than cvmbuild's [overlay.files] mechanism — cvmbuild resolves overlay
# src paths relative to its CWD (the host management plane's working
# dir), so the explicit Docker COPY from the build context is the
# bulletproof option. The build context is the kcvm/ repo root
# (cvm.toml's `context = "../..").
COPY images/ubuntu-26.04-ssh-cvm/overlay/root/.ssh/authorized_keys /root/.ssh/authorized_keys
COPY images/ubuntu-26.04-ssh-cvm/overlay/usr/local/sbin/sshd-keygen /usr/local/sbin/sshd-keygen
COPY images/ubuntu-26.04-ssh-cvm/overlay/usr/local/sbin/firewall-relax /usr/local/sbin/firewall-relax

# Lock down perms (Docker COPY preserves source mode; redo here to be
# explicit and resistant to host umask quirks).
RUN chmod 700 /root/.ssh \
    && chmod 600 /root/.ssh/authorized_keys \
    && chmod 755 /usr/local/sbin/sshd-keygen \
    && chmod 755 /usr/local/sbin/firewall-relax

# /home is empty by design — anything written there is on the read-only
# rootfs. Operators wanting persistent state should add a [[verity_disks]]
# entry in their fork's cvm.toml; this test image is ephemeral.
