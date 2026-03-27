# katt

Pure TypeScript TEE attestation verification library. Zero runtime dependencies, WebCrypto only.

Verifies hardware attestation from Intel TDX and AMD SEV-SNP confidential VMs, plus Sigstore supply-chain provenance bundles.

## Runtimes

**Bun** (primary) and **browsers**. Pure TypeScript + WebCrypto — runs anywhere with `crypto.subtle`.

### Bun

```bash
# Run tests
bun test test/

# Fetch collateral updates
bun run scripts/katt/fetch-collateral.ts
bun run scripts/katt/fetch-sev-collateral.ts
bun run scripts/katt/fetch-trusted-root.ts
```

### Browser

`katt/index.ts` is the browser-safe entry point — zero Node.js or Deno APIs. Bundle with Bun, esbuild, Rollup, or Vite.

All crypto uses the Web Crypto API (`crypto.subtle`), available in all modern browsers.

## What it verifies

### Intel TDX

Full 7-step TDX quote verification:

1. Parse quote structure (v4/v5)
2. Verify ECDSA P-256 quote body signature
3. Verify QE report hash (attestation key binding)
4. Parse PEM certificate chain from quote
5. Verify cert chain up to Intel Root CA (baked in)
6. Verify QE report signature with PCK key
7. Policy checks (debug mode, expected MRTD, report data)

Optional collateral checks: PCK CRL revocation, TCB level matching with advisory tracking.

```typescript
import { verifyTdxQuote } from "@katt/tdx/verify.ts";

const result = await verifyTdxQuote(quoteBytes);
if (result.valid) {
  console.log('MRTD:', result.mrtd);
  console.log('Report data:', result.reportData);
}
```

### AMD SEV-SNP

Full 4-step SEV-SNP report verification:

1. Parse attestation report
2. Verify AMD cert chain (ARK -> ASK -> VCEK, RSA-PSS SHA-384)
3. Verify report signature (ECDSA P-384)
4. Policy checks (debug mode, expected measurement, report data)

Supports Milan, Genoa, and Turin processors. Baked-in AMD root certs and CRLs with staleness tracking.

```typescript
import { verifySevReport } from "@katt/sev/verify.ts";

const result = await verifySevReport(reportBytes, vcekDer, {
  skipDateCheck: false,
});
if (result.valid) {
  console.log('Measurement:', result.measurement);
  console.log('Product:', result.productName);
}
```

### Sigstore

Verifies Sigstore bundles (DSSE envelopes with Rekor transparency log entries):

- Fulcio certificate chain verification with SCT validation (RFC 6962)
- Rekor transparency log entry verification with Merkle inclusion/checkpoint proofs
- DSSE signature verification
- Certificate time validation against verified timestamps

```typescript
import { verifySigstoreBundle } from "@katt/sigstore/verify.ts";

const result = await verifySigstoreBundle(bundleJson, {
  expectedDigest: '7e76d5a6d81f19ecdc1f3c18c8f0cf5b89d22ea107a05a1ae23ce46e79270f26',
  expectedRepo: 'your-org/your-repo',
});
if (result.valid) {
  console.log('OIDC Issuer:', result.oidcIssuer);
  console.log('Source Repo:', result.sourceRepo);
  console.log('Measurements:', result.measurements);
}
```

### Provenance

Bridges Sigstore and TEE verification: verifies a Sigstore bundle contains a valid build provenance predicate matching a specific container image digest.

```typescript
import { verifyCodeProvenance } from "@katt/provenance.ts";
import { verifyTdxQuote } from "@katt/tdx/verify.ts";

const teeResult = await verifyTdxQuote(quoteBytes);
const result = await verifyCodeProvenance(bundleJson, teeResult, {
  expectedDigest: '7e76d5a6d81f19ecdc1f3c18c8f0cf5b89d22ea107a05a1ae23ce46e79270f26',
  expectedRepo: 'your-org/your-repo',
});
```

## Architecture

```
katt/
  index.ts          Browser-safe entry point
  types.ts          All type definitions
  der.ts            DER/ASN.1 parser
  cert.ts           Certificate chain + CRL verification
  util.ts           Hex encoding, constant-time comparison
  provenance.ts     Sigstore + TEE bridge
  tdx/
    parse.ts        TDX quote parser
    verify.ts       Full TDX verification pipeline
    certs.ts        Baked Intel Root CA
    collateral.ts   TCB level matching, CRL checking
    fmspc.ts        PCK extension extraction
  sev/
    parse.ts        SEV-SNP report parser
    verify.ts       Full SEV verification pipeline
    certs.ts        Baked AMD root certs (Milan/Genoa/Turin)
    collateral.ts   CRL checking, live CRL fetching
  sigstore/
    verify.ts       Sigstore bundle verification
    dsse.ts         DSSE envelope parsing + signature verification
    fulcio.ts       Fulcio cert chain + SCT verification
    rekor.ts        Rekor tlog entry + Merkle proof verification
    types.ts        Sigstore-specific types
```

## Collateral

Baked-in collateral files (`*.generated.ts`) provide offline verification without network access:

- **TDX**: Intel TCB Info, PCK CRL, QE Identity
- **SEV-SNP**: AMD CRLs per processor family (Milan, Genoa, Turin)

Collateral has expiry dates. The `collateralStale` field in verification results indicates when baked data has passed its `nextUpdate`. Use `liveCollateral: true` to fetch fresh data from Intel PCS / AMD KDS APIs.

## Tests

Tests in `test/katt/` with local fixtures in `test/katt/fixtures/`.

```bash
bun test test/katt/
```

Fixture migration docs:
- `docs/katt/server-fixture-runbook.md` — short execution checklist for your own TDX/SEV servers + Sigstore bundle
- `docs/katt/collect-test-fixtures.md` — full replacement plan and context

## Design Principles

- **Zero dependencies**: No npm packages. Pure TypeScript + WebCrypto.
- **Browser-compatible**: `katt/index.ts` uses no Node.js APIs. Works in browsers with a bundler.
- **Offline-first**: Baked-in root certs and collateral. Network only needed for live collateral refresh.
- **Fail-closed by default**: CRL and TCB checks are enabled by default and require collateral to be present. Collateral signatures are cryptographically verified against Intel Root CA (`requireSignedCollateral` defaults to `true`). Set `skipCrlCheck: true` / `skipTcbCheck: true` to relax.

## Security Considerations

### Known Limitations

**`liveTrustedRoot` fetches Sigstore root without TUF verification.** When `liveTrustedRoot: true` is enabled, the trusted root JSON is fetched directly from GitHub (`sigstore/root-signing`) without verifying TUF metadata or pinned bootstrap keys. An attacker who controls transport or the GitHub source could substitute Fulcio/Rekor/CT/TSA keys and make forged bundles verify.

This is accepted because:
- `liveTrustedRoot` is **opt-in** — disabled by default. The default path uses a baked-in trusted root that ships with the library and is verified at build time.
- Implementing a full [TUF client](https://theupdateframework.io/) (root rotation, delegated targets, snapshot/timestamp metadata, threshold signatures) is a large scope increase incompatible with the library's zero-dependency, browser-compatible design.
- Callers who need authenticated root updates should implement TUF externally and pass the verified root via the `trustedRoot` parameter.

**Provenance API does not enforce challenge/nonce freshness.** `verifyCodeProvenance()` compares Sigstore predicate measurements against TEE attestation results but does not mandate `expectedReportData` (challenge binding). A replayed TEE quote with the same measurement would pass if the caller did not bind a challenge earlier.

This is accepted because:
- Freshness is the **caller's responsibility** at the TEE layer. Callers bind a nonce by passing `expectedReportData` to `verifyTdxQuote()` or `verifySevReport()` before calling `verifyCodeProvenance()`.
- The provenance API is a convenience bridge between Sigstore and TEE verification. Mandating freshness at this layer would impose a specific protocol (challenge-response) that may not fit all use cases (e.g., batch verification, offline attestation audit).
- The `teeResult.valid` check ensures the TEE attestation was cryptographically verified — but callers must ensure it was also fresh.

**Checkpoint signer selection uses 4-byte key hint.** Rekor checkpoint signatures follow the [signed note format](https://pkg.go.dev/golang.org/x/mod/sumdb/note), where signer identity is conveyed via a 4-byte key hint (truncated key ID hash). This is not a strong cryptographic binding to a specific key.

This is accepted because:
- The 4-byte hint is only used for **key selection**, not authentication. The actual security guarantee comes from ECDSA/Ed25519 signature verification — if the wrong key is selected, the signature simply won't verify.
- This is the standard format defined by the Go `sumdb/note` package and used by all Sigstore/Rekor deployments. Deviating would break interoperability.

### Collateral Staleness

Stale collateral (CRL/TCB data past its `nextUpdate`) is **reported but not rejected by default**. The `collateralStale` field in verification results indicates when baked data is outdated. Set `rejectStaleCollateral: true` to fail verification on stale data, or use `liveCollateral: true` to fetch fresh collateral from Intel PCS / AMD KDS.
