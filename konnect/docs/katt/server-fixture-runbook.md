# katt Server Fixture Runbook

Purpose: collect your own attestation artifacts from your own TDX and SEV-SNP servers, then replace third-party `katt` test fixtures.

This is the short execution runbook. For deeper context, see `docs/collect-test-fixtures.md`.

## Outputs you need

Copy these files back to your dev machine:

```text
# From TDX server
tdx_quote_1.bin
tdx_quote_2.bin
tdx_quote_3.bin

# From SEV-SNP server
attestation_report.bin
vcek.der
```

And from CI (not from a TEE server):

```text
sigstore-bundle.json
```

## 1) TDX server commands

Run on the TDX guest:

```bash
set -euo pipefail

dmesg | grep -i tdx
ls -l /dev/tdx_guest

# Prefer configfs-tsm path (kernel support required)
sudo mkdir -p /sys/kernel/config
sudo mount -t configfs none /sys/kernel/config || true
ls /sys/kernel/config/tsm/report
```

Generate 3 quotes with different report data:

```bash
set -euo pipefail

gen_quote () {
  local name="$1"
  local hex64="$2"
  sudo mkdir -p "/sys/kernel/config/tsm/report/${name}"
  echo -n "${hex64}" | xxd -r -p | sudo tee "/sys/kernel/config/tsm/report/${name}/inblob" >/dev/null
  sudo cat "/sys/kernel/config/tsm/report/${name}/outblob" > "${name}.bin"
  sudo rmdir "/sys/kernel/config/tsm/report/${name}"
}

# 64 bytes = 128 hex chars
ZERO64="$(printf '0%.0s' {1..128})"
KNOWN32="$(echo -n 'katt-tdx-known' | sha256sum | cut -d' ' -f1)"  # 32 bytes
KNOWN64="${KNOWN32}$(printf '0%.0s' {1..64})"                      # pad to 64 bytes
RAND64="$(head -c 64 /dev/urandom | xxd -p -c 128)"

gen_quote tdx_quote_1 "${ZERO64}"
gen_quote tdx_quote_2 "${KNOWN64}"
gen_quote tdx_quote_3 "${RAND64}"

ls -lh tdx_quote_*.bin
```

If `/sys/kernel/config/tsm/report` is not available, use the fallback in `docs/collect-test-fixtures.md`.

## 2) SEV-SNP server commands

Run on the SEV-SNP guest:

```bash
set -euo pipefail

dmesg | grep -i sev
ls -l /dev/sev-guest
```

Generate SEV report using configfs-tsm:

```bash
set -euo pipefail

REQ32="$(echo -n 'katt-sev-known' | sha256sum | cut -d' ' -f1)"
REQ64="${REQ32}$(printf '0%.0s' {1..64})"

sudo mkdir -p /sys/kernel/config
sudo mount -t configfs none /sys/kernel/config || true

sudo mkdir -p /sys/kernel/config/tsm/report/sev1
echo -n "${REQ64}" | xxd -r -p | sudo tee /sys/kernel/config/tsm/report/sev1/inblob >/dev/null
sudo cat /sys/kernel/config/tsm/report/sev1/outblob > attestation_report.bin
sudo rmdir /sys/kernel/config/tsm/report/sev1

ls -lh attestation_report.bin
```

Fetch VCEK for the exact report:

```bash
set -euo pipefail

python3 - <<'PY'
from pathlib import Path
import struct
import subprocess

rep = Path("attestation_report.bin").read_bytes()
if len(rep) < 0x1A0:
    raise SystemExit("attestation_report.bin too small")

# AMD SNP report layout offsets used by katt parser:
# 0x188 = family, 0x189 = model, 0x18A = stepping
family = rep[0x188]
model = rep[0x189]
stepping = rep[0x18A]

# chip_id is 64 bytes at 0x1A0
chip_id = rep[0x1A0:0x1A0+64].hex()

# reported_tcb is uint64 LE at 0x180
reported_tcb = struct.unpack_from("<Q", rep, 0x180)[0]
bl_spl   = (reported_tcb >>  0) & 0xFF
tee_spl  = (reported_tcb >>  8) & 0xFF
snp_spl  = (reported_tcb >> 48) & 0xFF
ucode_spl= (reported_tcb >> 56) & 0xFF

# crude product mapping used in katt:
product = "Milan"
if family == 0x19 and model == 0x11:
    product = "Genoa"
elif family == 0x1A and model == 0x02:
    product = "Turin"

url = (
    f"https://kdsintf.amd.com/vcek/v1/{product}/{chip_id}"
    f"?blSPL={bl_spl}&teeSPL={tee_spl}&snpSPL={snp_spl}&ucodeSPL={ucode_spl}"
)
print("Fetching:", url)
subprocess.check_call(["curl", "-fsSL", url, "-o", "vcek.der"])
print("Wrote vcek.der")
PY

ls -lh vcek.der
```

## 3) Sigstore bundle (CI)

Generate `sigstore-bundle.json` in GitHub Actions using cosign attest. Use the same flow from `docs/collect-test-fixtures.md` Part 3.

Minimum requirement for tests:
- bundle must contain your repo identity
- bundle must include your predicate with TDX/SEV measurements
- save final bundle as `sigstore-bundle.json`

## 4) Copy into katt fixtures

On your dev machine:

```bash
cp tdx_quote_1.bin code/katt/test/fixtures/tdx-quote-1.bin
cp tdx_quote_2.bin code/katt/test/fixtures/tdx-quote-2.bin
cp tdx_quote_3.bin code/katt/test/fixtures/tdx-quote-3.bin
cp attestation_report.bin code/katt/test/fixtures/sev-attestation-report.bin
cp vcek.der code/katt/test/fixtures/sev-vcek.der
cp sigstore-bundle.json code/katt/test/fixtures/sigstore-bundle.json
```

Then update test loaders/assertions:
- `test/fixtures.ts`
- `test/sigstore-verify.test.ts`
- `test/sigstore-crosscheck.test.ts`
- `test/collateral.test.ts`

## 5) Refresh collateral and run tests

```bash
cd code/katt
bun run scripts/fetch-collateral.ts
bun run scripts/fetch-sev-collateral.ts
bun test test/
```

