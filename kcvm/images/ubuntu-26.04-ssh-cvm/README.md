# ubuntu-26.04-ssh-cvm

Attestation-gated SSH into a confidential VM. The CVM exposes one TCP port to
the host (`8443/tcp`, kawa). sshd binds `127.0.0.1:22` *inside* the VM and is
reachable only after a successful Noise+attestation+post-quantum handshake.
konnect-proxy on the operator's laptop turns that into a local TCP listener
that `ssh` can connect to like any other host.

```
operator laptop                              CVM host                  CVM (this image)
┌───────────┐  ssh -p 2222   ┌──────────────┐  WSS+Noise+   ┌─────────────────────────┐
│ ssh       │ ─────────────▶ │ konnect-proxy│  attestation  │ kawa  →  tunnel.open=22 │
│           │ ◀───────────── │ :2222 → :8443│ ◀───────────▶ │ tunnel bytes ⇄ sshd:22  │
└───────────┘                └──────────────┘               │ /bin/bash + verity / RO │
                                                            └─────────────────────────┘
```

## Quick start

This image is part of the kcvm publish pipeline (GitHub → S3 → teehost).
Operators don't build it directly; teehost downloads the source on every
poll, runs `cvmbuild build`, and exposes the artifact at
`/var/lib/kawiri/kcvm/images/ubuntu-26.04-ssh-cvm/build/`.

```bash
# 1. Boot the VM (mock TEE on a non-TEE dev box; "snp" or "tdx" on real hardware)
curl -fsS -X POST http://localhost:8800/api/v1/vms \
    -H 'content-type: application/json' \
    -d '{"image_dir":"/var/lib/kawiri/kcvm/images/ubuntu-26.04-ssh-cvm",
         "tee":"none","mem":"2G","cpus":2}'
# → {"id":"vm-...","host_port":18443,...}

# 2. Wait for kawa inside the VM to come up (./api/v1/vms/<id> shows kawa.kind == "ready")

# 3. Run konnect-proxy on the host (or operator laptop, pointing at the CVM host's NetBird IP)
cd kawiri/konnect-proxy
bun src/main.ts \
    --to ws://127.0.0.1:18443 \
    --tunnel 2222:22 \
    --manifest ../kcvm/images/ubuntu-26.04-ssh-cvm/manifest.expected.json \
    --accept-mock                 # DEV-only flag; production runs reject mock

# 4. SSH in with the test key
ssh -i kawiri/kcvm/test-fixtures/ssh-keys/kawiri-test \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -p 2222 root@127.0.0.1
```

The `StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null` options are
correct here, not careless: the outer kawa attestation already proves the CVM
identity. SSH host-key verification on top would be redundant and would only
trip warnings since the host key is regenerated into tmpfs on every boot
(`sshd-keygen.service` writes `/run/sshd-keys/ssh_host_ed25519_key` before
sshd starts).

## Test SSH key (`kawiri-test`)

The repo ships only the **public** half at
`kcvm/test-fixtures/ssh-keys/kawiri-test.pub`. The matching private key lives
on the developer's machine and is gitignored. Anyone wanting to test the
end-to-end SSH flow either gets the private key out-of-band or generates
their own keypair and rebuilds the image with their pubkey baked in.

The pubkey is COPY'd into the rootfs at build time
(`/root/.ssh/authorized_keys`). A different pubkey produces a different SNP
launch digest / TDX MRTD, which is the right security property — your
authority over the CVM is bound to *your* image identity, not a shared
recipe.

## Forking for production

1. Generate your own keypair: `ssh-keygen -t ed25519 -f my-cvm -C "my-cvm-prod"`.
2. Replace `kawiri-test` in `overlay/root/.ssh/authorized_keys` with the
   contents of `my-cvm.pub`.
3. Rebuild via teehost UI / API. The new `manifest.json` will have different
   measurements; pin them in `manifest.expected.json`.
4. konnect-proxy clients use `--manifest path/to/your/manifest.expected.json`
   and never pass `--accept-mock`.

`KattValidator` rejects `platform=="mock"` by default. A production
deployment running on real SNP/TDX hardware will produce signed quotes that
match your pinned measurements; konnect-proxy will accept those and reject
anyone (including the host operator) trying to swap the image out for a
different build.

## Security boundary

- TEE (SNP/TDX) protects the VM's memory + disk against the **host
  operator** and against anyone with physical access to the box.
- Anyone with the private SSH key + a reachable kawa endpoint gets root
  inside the VM. **Treat the SSH key the way you'd treat any production
  credential** — it is the per-user authority, where the per-CVM
  authority is the SNP/TDX measurement.
- No password auth. `PasswordAuthentication=no`, `UsePAM=no`,
  `PermitRootLogin=prohibit-password`, `PubkeyAuthentication=yes`. All
  enforced via `-o` flags on sshd's command line, not just the config
  drop-in.
- `AllowAgentForwarding=no`, `AllowTcpForwarding=no`, `X11Forwarding=no`.
- The rootfs is read-only verity. SSH'd users can read everything but can't
  modify the disk image. Anything they want to persist needs a
  `[[verity_disks]]` entry — this image ships only one (`/mnt/config`) for
  kawa env vars.
- kawa stays on `hardening = "full"` so the trust-boundary process is tight
  even though sshd has to relax to `"minimal"` for PAM/passwd to work.

## Why some choices look weird

- **`extra_options = ["BindReadOnlyPaths=/etc/passwd.sshd:/etc/passwd"]`** on
  the sshd unit: cvmbuild's hardening pass unconditionally rewrites every
  login shell in `/etc/passwd` to `/usr/sbin/nologin`. Right call for
  chat-only CVMs, fatal for an SSH-CVM. The Dockerfile bakes a side-by-side
  `/etc/passwd.sshd` (with `root` shell `/bin/bash`) at a path cvmbuild
  doesn't touch, then sshd's mount namespace overmounts it onto
  `/etc/passwd`. Other services see the nologin'd file.
- **`exclude = ["no_shells", "no_shells_extended", ...]`** in `[assert]`:
  the production assert profile mandates that bash/sh/dash and every shell
  variant be in `[security].remove`. This image's whole point is to give a
  shell, so we exclude those checks. apt/dpkg/pip/dmsetup are still
  stripped — verity rootfs makes apt-install a no-op anyway, and pip is a
  common attacker tooling starting point.
- **No `[overlay.files]` block**: cvmbuild resolves overlay src paths
  relative to its own CWD (teehost's working dir), not the image directory.
  Files are COPY'd into the rootfs in the Dockerfile against the build
  context, which avoids the path-resolution ambiguity.

## Files

- `cvm.toml` — image config; sshd-keygen + sshd + kawa systemd units,
  KAWA_TUNNEL_PORTS=22, manifest declarations, assert excludes.
- `Dockerfile` — `FROM cvm-base:latest`; installs openssh-server + vim-tiny
  + less + iputils-ping; bakes `/etc/passwd.sshd` and the overlay tree.
- `overlay/root/.ssh/authorized_keys` — kawiri-test pubkey (per-user authority).
- `overlay/usr/local/sbin/sshd-keygen` — boot-time host-key generator (writes
  to `/run/sshd-keys` tmpfs).
- `overlay/etc/ssh/sshd_config.d/cvm.conf` — documentation only; sshd's real
  config is on its command line via `-o` flags.
- `manifest.expected.json` — pinned measurements from the first deterministic
  build; konnect-proxy verifies attestation against this.
