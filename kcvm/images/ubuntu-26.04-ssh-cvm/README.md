# ubuntu-26.04-ssh-cvm

A confidential VM with direct SSH. The CVM exposes one TCP port (sshd on
22 — declared via `[network].expose_port` in cvm.toml so teehost's
hostfwd targets it directly). Operators connect with any standard SSH
client and verify the launch measurement post-login by reading
`/sys/kernel/config/tsm/report` inside the CVM.

```
operator                    teehost host                  CVM
┌────────┐  ssh -p 18443  ┌──────────────┐  qemu hostfwd  ┌──────────────┐
│ ssh    │ ─────────────▶ │ :18443 → :22 │ ─────────────▶ │ sshd  :22    │
│        │ ◀───────────── │              │ ◀───────────── │              │
└────────┘                └──────────────┘                │ /bin/bash    │
                                                          │ verity / RO  │
                                                          └──────────────┘
```

## Quick start

```bash
# 1. Boot the VM via teehost (mock TEE on a non-TEE dev box; "snp"/"tdx" otherwise)
curl -fsS -X POST http://localhost:8800/api/v1/vms \
    -H 'content-type: application/json' \
    -d '{"image_dir":"/var/lib/kawiri/kcvm/images/ubuntu-26.04-ssh-cvm",
         "tee":"none","mem":"2G","cpus":2}'
# → {"id":"vm-...","host_port":18443,...}

# 2. Wait for the VM to come up (state == "running"). sshd-keygen.service
#    writes a fresh ed25519 host key into /run/sshd-keys, then sshd starts.

# 3. SSH in with the test key
ssh -i kawiri/kcvm/test-fixtures/ssh-keys/kawiri-test \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -p 18443 root@<vm-host>
```

The `StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null` options are
the right choice here, not careless: the SSH host key is regenerated into
tmpfs on every boot. Identity is anchored by the SNP launch digest /
TDX MRTD, which the operator verifies post-SSH (next section).

## Verifying the measurement post-login

Once SSHed in, read the live attestation from the kernel:

```bash
D=/sys/kernel/config/tsm/report/$$
mkdir "$D" && trap 'rmdir "$D"' EXIT
head -c 32 /dev/urandom > "$D/inblob"
echo "Provider:   $(cat $D/provider)"      # sev_guest | tdx_guest
case "$(cat $D/provider)" in
  sev_guest) dd if="$D/outblob" bs=1 skip=144 count=48 2>/dev/null | xxd -p -c 0 ;;
  tdx_guest) dd if="$D/outblob" bs=1 skip=184 count=48 2>/dev/null | xxd -p -c 0 ;;
esac
```

Compare the resulting hex to your pinned `manifest.expected.json` (committed
to git for this image: see `manifest.expected.json` in this directory).
Match ⇒ the host booted the bytes you built.

On a non-TEE dev box (no `/sys/kernel/config/tsm/report/<name>` provider),
the `mkdir` returns `No such device or address`, which is itself a
fingerprint: "this is not running on real TEE hardware."

## Test SSH key (`kawiri-test`)

The repo ships only the **public** half at
`kcvm/test-fixtures/ssh-keys/kawiri-test.pub`. The matching private key
lives on the developer's machine and is gitignored. Anyone wanting to test
the end-to-end SSH flow either gets the private key out-of-band or
generates their own keypair and rebuilds the image with their pubkey baked
in.

The pubkey is COPY'd into the rootfs at build time as
`/root/.ssh/authorized_keys`. A different pubkey produces a different SNP
launch digest / TDX MRTD — your authority over the CVM is bound to *your*
image identity, not a shared recipe.

## Forking for production

1. Generate your own keypair: `ssh-keygen -t ed25519 -f my-cvm -C "my-cvm-prod"`.
2. Replace the line in `overlay/root/.ssh/authorized_keys` with the contents
   of `my-cvm.pub`.
3. Rebuild via the teehost UI / API. The new `manifest.json` will have
   different measurements; pin them in `manifest.expected.json`.
4. Distribute `manifest.expected.json` (or just the launch digest) to the
   humans who will SSH in. They run the verification snippet above and
   confirm match.

## Security boundary

- **TEE (SNP/TDX) protects** VM memory + disk against the **host
  operator** and against anyone with physical access to the box.
- **Anyone with the private SSH key + a reachable host:port** gets root
  inside the VM. Treat the SSH key the way you'd treat any production
  credential — it is the per-user authority, where the per-CVM authority
  is the SNP measurement / TDX MRTD.
- **No password auth.** `PasswordAuthentication=no`, `UsePAM=no`,
  `PermitRootLogin=prohibit-password`, `PubkeyAuthentication=yes`.
- `AllowAgentForwarding=no`, `AllowTcpForwarding=no`, `X11Forwarding=no`.
- The rootfs is read-only verity. SSH'd users can read everything but
  can't modify the disk image. Anything to persist needs a
  `[[verity_disks]]` entry in your fork.
- Attestation verification is **post-login, by the operator**. There's no
  cryptographic gate before bytes flow — that's the trade for using
  standard SSH instead of a custom transport.

## Why some choices look weird

- **`extra_options = ["BindReadOnlyPaths=/etc/passwd.sshd:/etc/passwd"]`**
  on the sshd unit: cvmbuild's hardening pass unconditionally rewrites
  every login shell in `/etc/passwd` to `/usr/sbin/nologin` (right call
  for chat-only CVMs, fatal here). The Dockerfile bakes a side-by-side
  `/etc/passwd.sshd` (with `root` shell `/bin/bash`) at a path cvmbuild
  doesn't touch, then sshd's mount namespace overmounts it onto
  `/etc/passwd`. Other services see the nologin'd file unchanged.
- **`exclude = ["no_shells", "no_shells_extended"]`** in `[assert]`: the
  production assert profile mandates shells in `[security].remove`. This
  image's whole point is to give a shell, so we exclude those checks.
  apt/dpkg/pip/dmsetup are still stripped — verity rootfs makes
  apt-install a no-op anyway.
- **sshd on port 22 (and `[network]` block in cvm.toml)**: teehost reads
  `[network].expose_port` from each image's cvm.toml and uses it as the
  guest-side hostfwd target, so this image gets a normal SSH port
  inside. The `probe = "tcp"` field tells teehost to liveness-check by
  connecting to the port instead of running the kawa /health probe (which
  would hang since there's no kawa here). Inference images that don't
  declare `[network]` keep working unchanged via the back-compat default
  (kawa on 8443).

## Persistent encrypted storage (since v0.4.0)

teehost can attach an operator-managed writable qcow2 to the VM at boot
time (boot wizard's "Data disk (GB)" field, or `data_disk_gb` in the
boot request). The image bundles `cryptsetup` and the `dm-crypt`
kernel module so the operator can LUKS-format the disk post-login with
**their own passphrase** — teehost never sees the plaintext, the host
never has the key.

Inside the VM the disk shows up as
`/dev/disk/by-id/virtio-teehost-data` (a stable symlink that survives
re-enumeration when other images change verity-disk counts). First-time
setup:

```bash
cryptsetup luksFormat /dev/disk/by-id/virtio-teehost-data
cryptsetup luksOpen /dev/disk/by-id/virtio-teehost-data data
mkfs.ext4 /dev/mapper/data
mount /dev/mapper/data /var/lib/docker
systemctl restart docker
```

On every subsequent boot:

```bash
cryptsetup luksOpen /dev/disk/by-id/virtio-teehost-data data
mount /dev/mapper/data /var/lib/docker
systemctl restart docker
```

The qcow2 file persists across kill/restart. Explicit purge from the
VM detail page in the teehost UI when stopped.

Security model:
- Host operator sees the qcow2 file (it's on host disk) but only as
  ciphertext after `luksFormat` — LUKS does its job.
- Passphrase lives in the operator's head; entered over SSH which is
  itself running inside the TEE-encrypted VM memory, so the host
  never sees it on the wire either.
- This trades the (planned) attested-key-delivery automation for
  human-types-passphrase-every-boot. Right call for an SSH-CVM dev
  box; wrong call for an unattended fleet.

Adding the disk does **not** change the launch measurement — the
SNP `LAUNCH_DIGEST` covers OVMF + kernel + initrd + cmdline + VMSA +
CPUID, not device topology. Same `manifest.expected.json` whether
the VM was booted with 0, 1, or N data disks.

## Docker (since v0.3.0)

The image ships `docker.io` from Ubuntu's archive, plus the supporting
kernel modules (`overlay`, `bridge`, `br_netfilter`, `veth`, `nf_nat`,
`iptable_nat`, `ipt_MASQUERADE`, `ip_tables`, `xt_addrtype`,
`xt_conntrack`) loaded from initrd so they're available before
`lock_modules` seals modprobe. `/var/lib/docker` is a tmpfs (kernel
default size, ~50% of VM RAM), so:

- containers and images live in memory and are wiped on every boot
- `docker pull` from the public internet is **blocked** by cvmbuild's
  `outbound = "deny"` nftables policy (the platform's zero-trust check
  rejects `outbound = "allow"`). The supported workflows are:
  - **`docker load`** from a tarball SCP'd in over the SSH session:
    `docker save myimg | ssh -p 18443 root@host docker load`
  - **`docker build`** with a base image already loaded into
    `/var/lib/docker` (no `FROM` external)
  - **flush the firewall yourself**: you're root in the VM, so
    `nft flush ruleset` followed by Docker's own iptables setup
    will let `docker pull` reach the registry. This relaxes the
    cvmbuild-applied policy *for this boot only*; reboot restores it.

Forks that want persistent Docker state (images survive reboot) should
replace the `[[services.mounts]]` for `/var/lib/docker` with a
`[[verity_disks]]`-backed writable LV — same pattern the inference
images use for `/mnt/models`.

The `docker` group is created by the package post-install (and
defensively in the Dockerfile). Root in the VM is implicitly able to
talk to `/var/run/docker.sock`; on a fork that adds a non-root user,
`usermod -aG docker <name>` gives them Docker access.

## Files

- `cvm.toml` — image config; sshd-keygen + sshd systemd units, manifest
  declarations, assert excludes, `/var/lib/docker` tmpfs mount,
  Docker-required initrd modules.
- `Dockerfile` — `FROM cvm-base:latest`; installs openssh-server +
  vim-tiny + less + iputils-ping + docker.io; bakes `/etc/passwd.sshd`
  and the overlay tree; enables `docker.socket` / `docker.service` /
  `containerd.service`.
- `overlay/root/.ssh/authorized_keys` — kawiri-test pubkey.
- `overlay/usr/local/sbin/sshd-keygen` — boot-time host-key generator
  (writes to `/run/sshd-keys` tmpfs).
- `manifest.expected.json` — pinned measurements from the first
  deterministic build, used for the post-login verification.
