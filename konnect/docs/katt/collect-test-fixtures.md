# Collecting Test Fixtures for katt

This guide explains how to generate all test fixtures from your own TDX and SEV-SNP
machines, replacing all external dependencies (confer, phala, edgeless, tinfoil).

Quick path: if you only need the commands to run on servers, start with
`docs/server-fixture-runbook.md`.

---

## What We're Removing and Why

### External Dependencies and Their Licenses

| Source | Repo | License | Status | Action |
|--------|------|---------|--------|--------|
| **confer** (Entropy) | [entropyxyz/tdx-quote](https://github.com/entropyxyz/tdx-quote) | **AGPL-3.0** | MUST REMOVE | Replace TDX quotes + Intel Root CA cert |
| **tinfoil** | [tinfoilsh/*](https://github.com/tinfoilsh) | **AGPL-3.0** | MUST REMOVE | Replace Sigstore bundle |
| **phala** | [Phala-Network/dcap-qvl](https://github.com/Phala-Network/dcap-qvl) | MIT | OK but removing | Replace TDX quote |
| **edgeless** | [google/go-sev-guest](https://github.com/google/go-sev-guest) (edgeless fork) | Apache 2.0 | OK but removing | Replace SEV report + VCEK |
| **sigstore-conformance** | [sigstore/sigstore-conformance](https://github.com/sigstore/sigstore-conformance) | Apache 2.0 | **KEEPING** | No action needed |

**confer/tdx-quote** and **tinfoil** are both **AGPL-3.0** — a copyleft license
that requires source code disclosure for network services. We are using their
test data files (binary quotes, Sigstore bundles) not their code, but to be
clean we're replacing everything.

**phala/dcap-qvl** (MIT) and **edgeless/go-sev-guest** (Apache 2.0) are
permissive licenses — legally fine to keep. We're replacing them anyway so
katt has zero external test data dependencies.

**sigstore-conformance** (Apache 2.0) stays — it's the official Sigstore
project's test suite and tests a different code path (SLSA provenance
predicate vs our TEE measurement predicate).

### Files to Remove

After replacement, these external repo paths will no longer be referenced:

```
references/download/inference/
  confer/repos/tdx-quote/                      # AGPL-3.0 — REMOVING
    tests/test-quotes/v4_quote.dat             #   → replaced by tdx-quote-1.bin
    tests/test-quotes/known_pck_quote_1.dat    #   → replaced by tdx-quote-2.bin
    tests/test-quotes/known_pck_quote_2.dat    #   → replaced by tdx-quote-3.bin
    src/pck/Intel_SGX_Provisioning_Certification_RootCA.cer
                                               #   → already baked in src/tdx/certs.ts
                                               #     (identical cert, loaded from hex)
  phala/repos/dcap-qvl/                        # MIT — REMOVING anyway
    sample/tdx_quote                           #   → replaced by one of our TDX quotes

  edgeless/repos/go-sev-guest/                 # Apache 2.0 — REMOVING anyway
    verify/testdata/attestation.bin            #   → replaced by sev-attestation-report.bin
    verify/testdata/vcek.testcer               #   → replaced by sev-vcek.der
```

### Code Changes After Replacement

These files reference external repos and will be rewritten:

| File | What Changes |
|------|-------------|
| `test/fixtures.ts` | Remove all external repo paths. Load everything from `test/fixtures/` |
| `test/fixtures/sigstore-bundle.json` | Replace tinfoil bundle with our own (AGPL-3.0 → ours) |
| `test/sigstore-verify.test.ts` | Update expected repo URI, digest, measurements |
| `test/sigstore-crosscheck.test.ts` | May need minor assertion updates |
| `test/collateral.test.ts` | Update `phala_tdx_quote` references to our quote names |

### What Stays (No License Concern)

These are NOT external dependencies — they're public infrastructure data:

| Data | Source | Why It's Fine |
|------|--------|--------------|
| Intel SGX Root CA cert | Intel (baked in `src/tdx/certs.ts`) | Public CA cert, same for everyone |
| AMD ARK/ASK certs | AMD (baked in `src/sev/certs.ts`) | Public CA certs for Milan/Genoa/Turin |
| Intel TCB Info + CRLs | Intel PCS API (auto-fetched) | Public API, no license |
| AMD CRLs | AMD KDS API (auto-fetched) | Public API, no license |
| Sigstore trusted root | Sigstore (auto-fetched) | Apache 2.0, public infrastructure |
| `sigstore-conformance-bundle.json` | sigstore-conformance | Apache 2.0 |

---

## What We Need (Summary)

| Artifact | Source Machine | Format | Count |
|----------|---------------|--------|-------|
| TDX quotes | TDX server | Binary (.bin) | 2-3 |
| SEV-SNP attestation report | SEV-SNP server | Binary (.bin) | 1 |
| VCEK certificate | SEV-SNP server | DER (.der) | 1 |
| Sigstore bundle | GitHub Actions | JSON (.json) | 1 |

Intel Root CA cert + collateral (TCB Info, CRLs) are already fetched automatically
by our scripts from Intel/AMD APIs. No machine access needed for those.

---

## Part 1: TDX Server

### Prerequisites

```bash
# Verify you're in a TDX guest
dmesg | grep -i tdx
# Should show: "tdx: Guest detected"

# Check the device exists
ls -la /dev/tdx_guest
# Should show: crw------- 1 root root 10, 125 ... /dev/tdx_guest
```

If `/dev/tdx_guest` doesn't exist but you're in a TDX VM, try:
```bash
sudo modprobe tdx_guest
```

### Step 1: Install quote generation tool

**Option A: Use tdx-tools (Python)**
```bash
pip install pytdxattest
# or clone: git clone https://github.com/intel/tdx-tools
```

**Option B: Use configfs-tsm (Linux 6.7+, recommended)**
```bash
# Check if configfs-tsm is available (Linux 6.7+)
ls /sys/kernel/config/tsm/report/
```

**Option C: Compile a minimal C program**
```bash
cat > gen_tdx_quote.c << 'CEOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdint.h>

/* TDX guest ioctl definitions */
#define TDX_CMD_GET_REPORT0  _IOWR('T', 1, struct tdx_report_req)
#define TDX_CMD_GET_QUOTE    _IOR('T', 4, struct tdx_quote_hdr)

struct tdx_report_req {
    uint8_t  reportdata[64];   /* input: 64 bytes of report data */
    uint8_t  tdreport[1024];   /* output: TD report */
};

struct tdx_quote_hdr {
    uint64_t version;
    uint64_t status;
    uint32_t in_len;
    uint32_t out_len;
    uint8_t  data[];           /* in: TD report, out: quote */
};

int main(int argc, char *argv[]) {
    const char *outfile = argc > 1 ? argv[1] : "tdx_quote.bin";
    const char *report_data_hex = argc > 2 ? argv[2] : NULL;

    /* Open TDX guest device */
    int fd = open("/dev/tdx_guest", O_RDWR);
    if (fd < 0) {
        perror("open /dev/tdx_guest");
        return 1;
    }

    /* Step 1: Get TD Report */
    struct tdx_report_req req;
    memset(&req, 0, sizeof(req));

    /* Set report data (64 bytes) - use provided hex or zeros */
    if (report_data_hex) {
        size_t len = strlen(report_data_hex);
        for (size_t i = 0; i < 64 && i * 2 < len; i++) {
            sscanf(report_data_hex + i * 2, "%2hhx", &req.reportdata[i]);
        }
    }

    if (ioctl(fd, TDX_CMD_GET_REPORT0, &req) < 0) {
        perror("TDX_CMD_GET_REPORT0");
        close(fd);
        return 1;
    }
    fprintf(stderr, "Got TD Report (1024 bytes)\n");

    /* Step 2: Get Quote from QE via quote generation service */
    size_t buf_size = sizeof(struct tdx_quote_hdr) + 1024 + 32768;
    struct tdx_quote_hdr *hdr = calloc(1, buf_size);
    hdr->version = 1;
    hdr->in_len = 1024;
    hdr->out_len = 32768;
    memcpy(hdr->data, req.tdreport, 1024);

    if (ioctl(fd, TDX_CMD_GET_QUOTE, hdr) < 0) {
        perror("TDX_CMD_GET_QUOTE");
        fprintf(stderr,
            "\nQuote generation failed. This usually means:\n"
            "  - qgsd (quote generation service) is not running\n"
            "  - PCCS (provisioning cache service) is not configured\n"
            "\nTry: sudo systemctl status qgsd\n"
            "Or use configfs-tsm method instead.\n");
        free(hdr);
        close(fd);
        return 1;
    }

    fprintf(stderr, "Got TDX Quote (%u bytes)\n", hdr->out_len);

    /* Write quote to file */
    FILE *f = fopen(outfile, "wb");
    fwrite(hdr->data, 1, hdr->out_len, f);
    fclose(f);

    fprintf(stderr, "Wrote %s\n", outfile);
    free(hdr);
    close(fd);
    return 0;
}
CEOF

gcc -o gen_tdx_quote gen_tdx_quote.c
```

### Step 2: Generate TDX Quotes

We need 2-3 quotes with different report data to test various scenarios.

**Method A: configfs-tsm (Linux 6.7+, simplest)**

```bash
# Quote 1: with zeros report data
sudo mkdir -p /sys/kernel/config/tsm/report/quote1
echo -n "0000000000000000000000000000000000000000000000000000000000000000" | \
  xxd -r -p | sudo tee /sys/kernel/config/tsm/report/quote1/inblob > /dev/null
sudo cat /sys/kernel/config/tsm/report/quote1/outblob > tdx_quote_1.bin
sudo rmdir /sys/kernel/config/tsm/report/quote1

# Quote 2: with custom report data (e.g., SHA-256 of "kawiri-test")
REPORT_DATA=$(echo -n "kawiri-test" | sha256sum | cut -d' ' -f1)
# Pad to 64 bytes (128 hex chars)
REPORT_DATA="${REPORT_DATA}$(printf '0%.0s' {1..64})"
sudo mkdir -p /sys/kernel/config/tsm/report/quote2
echo -n "${REPORT_DATA}" | xxd -r -p | \
  sudo tee /sys/kernel/config/tsm/report/quote2/inblob > /dev/null
sudo cat /sys/kernel/config/tsm/report/quote2/outblob > tdx_quote_2.bin
sudo rmdir /sys/kernel/config/tsm/report/quote2

# Quote 3: with random report data
RANDOM_DATA=$(head -c 64 /dev/urandom | xxd -p -c 128)
sudo mkdir -p /sys/kernel/config/tsm/report/quote3
echo -n "${RANDOM_DATA}" | xxd -r -p | \
  sudo tee /sys/kernel/config/tsm/report/quote3/inblob > /dev/null
sudo cat /sys/kernel/config/tsm/report/quote3/outblob > tdx_quote_3.bin
sudo rmdir /sys/kernel/config/tsm/report/quote3
```

**Method B: C program**

```bash
sudo ./gen_tdx_quote tdx_quote_1.bin
sudo ./gen_tdx_quote tdx_quote_2.bin "$(echo -n 'kawiri-test' | sha256sum | cut -d' ' -f1)"
sudo ./gen_tdx_quote tdx_quote_3.bin "$(head -c 64 /dev/urandom | xxd -p -c 128)"
```

**Method C: pytdxattest**

```python
from pytdxattest import TdxAttest
import hashlib

tdx = TdxAttest()

# Quote 1: zeros
quote1 = tdx.get_quote(report_data=bytes(64))
with open("tdx_quote_1.bin", "wb") as f:
    f.write(quote1)

# Quote 2: with custom data
rd = hashlib.sha256(b"kawiri-test").digest() + bytes(32)
quote2 = tdx.get_quote(report_data=rd)
with open("tdx_quote_2.bin", "wb") as f:
    f.write(quote2)
```

### Step 3: Verify the quotes look right

```bash
# Each file should be 4000-6000 bytes
ls -la tdx_quote_*.bin

# First 2 bytes should be 04 00 (version 4, little-endian)
xxd -l 8 tdx_quote_1.bin
# Expected: 0400 0200 0000 8100
#           ^^^^ version=4
#                ^^^^ att_key_type=2 (ECDSA P-256)
#                     ^^^^ reserved
#                          ^^^^ tee_type=0x81 (TDX)
```

### Step 4: Extract the FMSPC from one quote

We need the FMSPC value so we can fetch matching Intel collateral.

```bash
# The FMSPC is in the PCK certificate's extensions.
# Our test suite extracts it automatically, but let's verify we can
# read the cert chain from the quote:

# Extract the PEM cert chain (starts after the fixed-size fields)
# This is easier to do with our own tooling after copying files.
# For now, just note the file sizes - they should be 4-6KB.
```

### Step 5: Record the MRTD

The MRTD is the TD measurement hash. It's needed for the `tdx-collateral.json`
fixture. After you copy the quotes to your dev machine, we'll extract this
using our parser. But if you want to see it now:

```bash
# MRTD is at offset 560 in the quote body (48 bytes)
# Quote body starts at offset 48 (after header)
# So MRTD is at absolute offset 48 + 512 = 560... actually let me be precise:
# Header: 48 bytes
# Body offset from header end:
#   teeTcbSvn: 0-15 (16 bytes)
#   mrseam: 16-63 (48 bytes)
#   mrsignerseam: 64-111 (48 bytes)
#   seamattributes: 112-119 (8 bytes)
#   tdattributes: 120-127 (8 bytes)
#   xfam: 128-135 (8 bytes)
#   mrtd: 136-183 (48 bytes)
# So MRTD absolute offset = 48 + 136 = 184

xxd -s 184 -l 48 tdx_quote_1.bin | cut -d: -f2 | tr -d ' \n'
echo  # newline
```

### What to copy off the TDX server

```
tdx_quote_1.bin    # Quote with zero report data
tdx_quote_2.bin    # Quote with known report data (SHA-256 of "kawiri-test")
tdx_quote_3.bin    # Quote with random report data
```

---

## Part 2: SEV-SNP Server

### Prerequisites

```bash
# Verify you're in an SEV-SNP guest
dmesg | grep -i sev
# Should show: "SEV-SNP: SNP guest registered"
# or: "Memory Encryption Features active: AMD SEV SEV-ES SEV-SNP"

# Check the device exists
ls -la /dev/sev-guest
# Should show: crw------- 1 root root 10, 124 ... /dev/sev-guest
```

If `/dev/sev-guest` doesn't exist:
```bash
sudo modprobe sev-guest
```

### Step 1: Install snpguest tool

**Option A: snpguest (Rust, recommended)**
```bash
# Install from crates.io
cargo install snpguest

# Or build from source
git clone https://github.com/virtee/snpguest
cd snpguest
cargo build --release
# Binary at: target/release/snpguest
```

**Option B: sev-guest-get-report (from AMD)**
```bash
git clone https://github.com/AMDESE/sev-guest
cd sev-guest
make
# Binary: sev-guest-get-report
```

**Option C: configfs-tsm (Linux 6.7+)**
```bash
ls /sys/kernel/config/tsm/report/
```

### Step 2: Generate SEV-SNP Attestation Report

**Method A: snpguest (recommended)**

```bash
# Generate report with random nonce (64 bytes report data)
sudo snpguest report attestation_report.bin request_data.bin --random

# Or with specific report data:
echo -n "kawiri-test-sev" | sha256sum | cut -d' ' -f1 | xxd -r -p > request_data.bin
# Pad to 64 bytes
dd if=/dev/zero bs=1 count=32 >> request_data.bin 2>/dev/null
sudo snpguest report attestation_report.bin request_data.bin
```

**Method B: configfs-tsm (Linux 6.7+)**

```bash
sudo mkdir -p /sys/kernel/config/tsm/report/sev1
echo -n "kawiri" | sha256sum | cut -d' ' -f1 | xxd -r -p | head -c 64 | \
  sudo tee /sys/kernel/config/tsm/report/sev1/inblob > /dev/null
sudo cat /sys/kernel/config/tsm/report/sev1/outblob > attestation_report.bin
sudo rmdir /sys/kernel/config/tsm/report/sev1
```

**Method C: Direct ioctl (C program)**

```bash
cat > gen_sev_report.c << 'CEOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdint.h>

/* From linux/sev-guest.h */
struct snp_report_req {
    uint8_t  user_data[64];
    uint32_t vmpl;
    uint8_t  rsvd[28];
};

struct snp_report_resp {
    uint32_t status;
    uint32_t report_size;
    uint8_t  rsvd[24];
    uint8_t  report[4000];
};

struct snp_guest_request_ioctl {
    uint8_t  msg_version;
    uint64_t req_data;
    uint64_t resp_data;
    union {
        uint64_t exitinfo2;
        struct {
            uint32_t fw_error;
            uint32_t vmm_error;
        };
    };
};

#define SNP_GET_REPORT _IOWR('S', 0x0, struct snp_guest_request_ioctl)

int main(int argc, char *argv[]) {
    const char *outfile = argc > 1 ? argv[1] : "attestation_report.bin";

    int fd = open("/dev/sev-guest", O_RDWR);
    if (fd < 0) {
        perror("open /dev/sev-guest");
        return 1;
    }

    struct snp_report_req *req = calloc(1, sizeof(*req));
    struct snp_report_resp *resp = calloc(1, sizeof(*resp));

    /* Set 64 bytes of report data */
    memcpy(req->user_data, "kawiri-sev-test\0", 16);
    req->vmpl = 0;

    struct snp_guest_request_ioctl ioctl_req = {
        .msg_version = 1,
        .req_data = (uint64_t)req,
        .resp_data = (uint64_t)resp,
    };

    if (ioctl(fd, SNP_GET_REPORT, &ioctl_req) < 0) {
        perror("SNP_GET_REPORT");
        free(req); free(resp); close(fd);
        return 1;
    }

    fprintf(stderr, "Got SEV-SNP report (%u bytes, status=%u)\n",
            resp->report_size, resp->status);

    FILE *f = fopen(outfile, "wb");
    fwrite(resp->report, 1, resp->report_size, f);
    fclose(f);

    fprintf(stderr, "Wrote %s\n", outfile);
    free(req); free(resp); close(fd);
    return 0;
}
CEOF

gcc -o gen_sev_report gen_sev_report.c
sudo ./gen_sev_report attestation_report.bin
```

### Step 3: Fetch the VCEK Certificate

The VCEK (Versioned Chip Endorsement Key) cert is fetched from AMD's KDS (Key
Distribution Service) using the chip ID and TCB version from the report.

**Method A: snpguest (recommended)**

```bash
# This reads the chip ID + TCB from the report and fetches from AMD KDS
sudo snpguest fetch vcek der . --attestation-report attestation_report.bin

# Output: vcek.der in current directory
```

**Method B: Manual fetch from AMD KDS**

```bash
# First, extract chip ID and TCB from the report
# Chip ID is at offset 416, 64 bytes
CHIP_ID=$(xxd -s 416 -l 64 -p attestation_report.bin | tr -d '\n')

# Current TCB is at offset 384, 8 bytes (little-endian)
# Boot loader, TEE, SNP, microcode SVN values
BOOT_LOADER=$(xxd -s 384 -l 1 -p attestation_report.bin)
TEE=$(xxd -s 385 -l 1 -p attestation_report.bin)
SNP=$(xxd -s 390 -l 1 -p attestation_report.bin)
MICROCODE=$(xxd -s 391 -l 1 -p attestation_report.bin)

# Determine product from report (family_id or check dmesg)
# Common products: Milan, Genoa, Turin
PRODUCT="Genoa"  # <-- CHANGE THIS to match your CPU

# Fetch VCEK from AMD KDS
curl -o vcek.der \
  "https://kdsintf.amd.com/vcek/v1/${PRODUCT}/${CHIP_ID}?blSPL=${BOOT_LOADER}&teeSPL=${TEE}&snpSPL=${SNP}&ucodeSPL=${MICROCODE}"

echo "Downloaded vcek.der ($(wc -c < vcek.der) bytes)"
```

### Step 4: Determine the CPU product family

```bash
# Check which AMD product family:
# This appears in the VCEK cert issuer CN
openssl x509 -in vcek.der -inform der -noout -issuer
# Should show: issuer=CN = SEV-Milan   or   SEV-Genoa   or   SEV-Turin

# Also check from the CPU itself:
cat /proc/cpuinfo | grep "model name" | head -1
# Milan = EPYC 7xx3 series
# Genoa = EPYC 9xx4 series
# Turin = EPYC 9xx5 series
```

### Step 5: Verify the report looks right

```bash
# Report should be exactly 1184 bytes
ls -la attestation_report.bin
# Expected: 1184 bytes

# First 4 bytes: version (should be 02 00 00 00 for v2)
xxd -l 4 attestation_report.bin
# Expected: 0200 0000

# VCEK cert should be 1000-2000 bytes DER
ls -la vcek.der

# Verify VCEK cert is valid X.509
openssl x509 -in vcek.der -inform der -noout -subject -issuer -dates
# Subject should contain chip info
# Issuer should be SEV-{Product}
# Dates should be current
```

### What to copy off the SEV-SNP server

```
attestation_report.bin    # Raw SEV-SNP attestation report (1184 bytes)
vcek.der                  # VCEK certificate from AMD KDS (DER format)
```

---

## Part 3: Sigstore Bundle (from GitHub Actions)

This requires a public GitHub repo. You'll sign a container image (or any OCI
artifact) with Sigstore, embedding TEE measurements in the predicate.

### Prerequisites

- A public GitHub repository (or create one for this purpose)
- GitHub Actions enabled
- `cosign` CLI (for local testing, optional)

### Step 1: Create the attestation workflow

Create `.github/workflows/attest.yml` in your repo:

```yaml
name: Generate TEE Attestation Bundle

on:
  push:
    tags: ['v*']
  workflow_dispatch:

permissions:
  contents: read
  id-token: write         # Needed for Sigstore OIDC
  packages: write         # Needed for GHCR push
  attestations: write     # Needed for gh attestation

jobs:
  attest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install cosign
        uses: sigstore/cosign-installer@v3

      - name: Log in to GHCR
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build and push a minimal image
        run: |
          # Create a minimal container image to attest
          echo "FROM alpine:latest" > Dockerfile
          echo 'CMD ["echo", "kawiri-test"]' >> Dockerfile

          IMAGE="ghcr.io/${{ github.repository }}/test-image:${{ github.sha }}"
          docker build -t "${IMAGE}" .
          docker push "${IMAGE}"

          # Get the digest
          DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "${IMAGE}" | cut -d@ -f2)
          echo "IMAGE_REF=${IMAGE}@${DIGEST}" >> "$GITHUB_ENV"
          echo "DIGEST=${DIGEST}" >> "$GITHUB_ENV"

      - name: Create TEE measurement predicate
        run: |
          # This predicate contains mock TEE measurements in the same
          # format as real ones. Replace these with actual measurements
          # from your TDX/SEV-SNP machines if you have them.
          #
          # Format: our custom predicate type with SNP + TDX measurements
          cat > predicate.json << 'EOF'
          {
            "snp_measurement": "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "tdx_measurement": {
              "rtmr0": "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
              "rtmr1": "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
              "rtmr2": "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
              "rtmr3": "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            }
          }
          EOF

          # IMPORTANT: If you have real measurements from your TDX/SEV servers,
          # replace the zeros above with the actual hex values:
          #
          # For SNP: the 'measurement' field from attestation_report.bin
          #   xxd -s 144 -l 48 -p attestation_report.bin | tr -d '\n'
          #
          # For TDX RTMRs: extract from a TDX quote
          #   Our parser will give you rtmr0-3 as hex strings

      - name: Attest with cosign (Sigstore bundle)
        run: |
          cosign attest \
            --yes \
            --type "https://kawiri.dev/predicate/tee-measurements/v1" \
            --predicate predicate.json \
            "${IMAGE_REF}"

      - name: Download the attestation bundle
        run: |
          # Use gh to download the attestation
          # This gives us the Sigstore bundle JSON
          gh attestation download \
            --owner "${{ github.repository_owner }}" \
            --repo "${{ github.repository }}" \
            --digest "${DIGEST}" \
            --format json \
            > attestation-response.json

          # Extract just the bundle (first attestation)
          cat attestation-response.json | \
            jq '.attestations[0].bundle' > sigstore-bundle.json

          echo "Bundle size: $(wc -c < sigstore-bundle.json) bytes"
          echo "Response size: $(wc -c < attestation-response.json) bytes"
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: sigstore-fixtures
          path: |
            sigstore-bundle.json
            attestation-response.json
            predicate.json
```

### Step 2: Trigger the workflow

```bash
# Tag a release to trigger the workflow
git tag v0.0.1
git push origin v0.0.1

# Or trigger manually from the Actions tab
```

### Step 3: Download the artifacts

After the workflow completes, download from the Actions run artifacts:
- `sigstore-bundle.json` - The Sigstore bundle (this replaces tinfoil's)
- `attestation-response.json` - The full response wrapper

### Alternative: Local cosign (if you have OIDC)

```bash
# Sign locally with keyless (browser-based OIDC)
cosign attest \
  --yes \
  --type "https://kawiri.dev/predicate/tee-measurements/v1" \
  --predicate predicate.json \
  ghcr.io/YOUR_ORG/YOUR_IMAGE@sha256:DIGEST

# Then download via gh CLI
gh attestation download \
  --owner YOUR_ORG \
  --repo YOUR_REPO \
  --digest sha256:DIGEST \
  --format json > attestation-response.json

jq '.attestations[0].bundle' attestation-response.json > sigstore-bundle.json
```

---

## Part 4: Updating the Test Fixtures

Once you have all artifacts on your dev machine, here's where to put them and
what to update.

### File placement

```
katt/
  test/
    fixtures/
      # New files (replace external repos):
      tdx-quote-1.bin               # TDX quote with zero report data
      tdx-quote-2.bin               # TDX quote with known report data
      tdx-quote-3.bin               # TDX quote with random report data
      sev-attestation-report.bin    # SEV-SNP attestation report
      sev-vcek.der                  # VCEK certificate (DER)

      # Updated files:
      sigstore-bundle.json          # YOUR Sigstore bundle (replaces tinfoil)
      sigstore-attestation-response.json  # YOUR attestation response

      # Keep as-is (already independent):
      sigstore-conformance-bundle.json    # Apache 2.0, from sigstore project
      tdx-collateral.json                 # Needs regeneration (see below)
```

### After placing files, we need to:

1. **Update `test/fixtures.ts`** to load from `test/fixtures/` instead of
   external repo paths

2. **Regenerate `tdx-collateral.json`** with collateral matching your TDX
   quote's FMSPC (run after extracting FMSPC from your quote)

3. **Update the Sigstore test expectations** (repo URI, measurements, digest)

4. **Run the full test suite** to verify everything works

I (Claude) will handle all of these code changes once you provide the files.

---

## Verification Checklist

Before copying files to your dev machine, verify:

### TDX Quotes
- [ ] Each file is 4000-6000 bytes
- [ ] First 2 bytes are `04 00` (version 4 little-endian)
- [ ] Bytes 5-8 are `00 00 81 00` (tee_type = TDX)
- [ ] At least 2 quotes with different report data

### SEV-SNP Report
- [ ] `attestation_report.bin` is exactly 1184 bytes
- [ ] First 4 bytes are `02 00 00 00` (version 2)
- [ ] `openssl x509 -in vcek.der -inform der -noout -subject` works
- [ ] VCEK issuer is `SEV-Milan`, `SEV-Genoa`, or `SEV-Turin`

### Sigstore Bundle
- [ ] `sigstore-bundle.json` is valid JSON
- [ ] Has `mediaType` containing `sigstore.bundle`
- [ ] Has `dsseEnvelope` with `payload` and `signatures`
- [ ] Has `verificationMaterial` with `tlogEntries` and `certificate`
- [ ] The predicate type is `https://kawiri.dev/predicate/tee-measurements/v1`

---

## Quick Reference: What Each Artifact Tests

| Artifact | Tests It Enables |
|----------|-----------------|
| TDX quotes | Quote parsing, ECDSA signature verification, cert chain validation, FMSPC extraction, measurement extraction |
| SEV report + VCEK | Report parsing, ECDSA P-384 signature verification, VCEK → ASK → ARK chain validation, product detection |
| Sigstore bundle | DSSE verification, Fulcio cert chain → CT log, Rekor tlog inclusion proof, measurement extraction from predicate |
| TDX collateral (auto-fetched) | TCB level matching, CRL revocation checking, collateral signature verification |
| SEV collateral (auto-fetched) | CRL signature verification, CRL revocation checking |

---

## Notes

- The Intel Root CA certificate is already baked into our code at
  `src/tdx/certs.ts` — it's the same for everyone, no need to collect it.

- AMD Root/Signing keys (ARK/ASK) are already baked into `src/sev/certs.ts`
  for Milan, Genoa, and Turin — no need to collect these.

- Intel collateral (TCB Info, QE Identity, PCK CRL) is auto-fetched by
  `scripts/fetch-collateral.ts`. After you get TDX quotes, we'll need to
  know the FMSPC to fetch matching collateral. Our parser extracts this
  automatically.

- AMD CRLs are auto-fetched by `scripts/fetch-sev-collateral.ts`.

- The `sigstore-conformance-bundle.json` stays as-is — it's from the
  official sigstore-conformance project (Apache 2.0 license) and tests
  a different code path (SLSA provenance predicate, different signer).

---

## After Replacement: Dependency Summary

Once all fixtures are replaced, katt's external data dependencies will be:

| Dependency | Type | License | Notes |
|-----------|------|---------|-------|
| Intel PCS API | Runtime (optional) | Public API | For live collateral fetch |
| AMD KDS API | Runtime (optional) | Public API | For live CRL/VCEK fetch |
| Sigstore public-good | Runtime (optional) | Apache 2.0 | Rekor, Fulcio, CT logs |
| sigstore-conformance bundle | Test fixture | Apache 2.0 | Cross-verification tests |
| Our own TDX quotes | Test fixture | Ours | Generated on our hardware |
| Our own SEV report | Test fixture | Ours | Generated on our hardware |
| Our own Sigstore bundle | Test fixture | Ours | Signed by our GitHub identity |

Zero AGPL. Zero copyleft. All test data is either ours or Apache 2.0.
