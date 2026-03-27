# katt Certificate Source Inventory And Replacement Plan

Date: 2026-02-19

Goal: track all certificate/trust-material sources currently used in `katt`, including third-party provenance, and define a strict "do not remove until replacement exists" migration path.

## Policy

- Do not remove any fixture/trust material that is still needed for passing tests.
- Replace AGPL-associated fixtures first (highest priority).
- MIT/Apache fixtures can remain temporarily, but must be tagged with origin and replacement status.
- Public trust infrastructure material (Intel/AMD/Sigstore roots, collateral APIs) is allowed to remain.

## A) Runtime trust anchors and collateral

| Path | Material | Origin | License Context | Status |
|---|---|---|---|---|
| `code/katt/src/tdx/certs.ts` | Intel SGX Provisioning Root CA (DER, baked hex) | Intel certificate distribution | Public PKI root cert | Keep |
| `code/katt/src/sev/certs.ts` | AMD ARK/ASK cert chains (Milan/Genoa/Turin) | AMD KDS/public certs | Public PKI certs | Keep |
| `code/katt/src/sigstore/trusted-root.ts` | Sigstore trusted root (Fulcio/Rekor/CT/TSA keys/certs) | `sigstore/root-signing` | Sigstore public-good (Apache-2.0 project) | Keep |
| `code/katt/src/tdx/collateral.generated.ts` | Intel TDX collateral (TCB/QE/CRL + issuer chains) | Intel PCS API | Public API data | Keep |
| `code/katt/src/sev/collateral.generated.ts` | AMD SEV CRLs | AMD KDS API | Public API data | Keep |

## B) Test fixtures currently in repo

| Path | Contains | Current Usage | Provenance | License Context | Replacement Needed |
|---|---|---|---|---|---|
| `code/katt/test/fixtures/sigstore-bundle.json` | DSSE bundle + Fulcio signing cert + Rekor entry | Used by sigstore/provenance tests | Historical Tinfoil attestation sample | AGPL-associated source project provenance | Yes (high) |
| `code/katt/test/fixtures/sigstore-attestation-response.json` | Attestation API response embedding bundle+cert | Stored fixture (not primary in current tests) | Historical Tinfoil response sample | AGPL-associated source project provenance | Yes (high) |
| `code/katt/test/fixtures/sigstore-conformance-bundle.json` | Sigstore conformance bundle + cert chain metadata | Used by crosscheck tests | `sigstore/sigstore-conformance` | Apache-2.0 | Optional (can keep) |
| `code/katt/test/fixtures/tdx-collateral.json` | Intel collateral snapshot + issuer chains | Used by collateral tests | Generated from Intel PCS (historically keyed to external quote context) | Public Intel API output | Refresh with your own quote FMSPC |

## C) Historical external fixture provenance (tracked for migration)

These were the original external sources referenced in test workflow planning:

| Historical Source | Example Material | License | Migration Rule |
|---|---|---|---|
| `entropyxyz/tdx-quote` (confer) | TDX quotes + Intel root cert file copy | AGPL-3.0 | Replace first, then remove dependency |
| `tinfoilsh/*` | Sigstore bundle/attestation samples | AGPL-3.0 | Replace first, then remove dependency |
| `Phala-Network/dcap-qvl` | TDX quote sample | MIT | Can keep temporarily, still mark/replace |
| `google/go-sev-guest` (edgeless usage) | SEV report + VCEK sample | Apache-2.0 | Can keep temporarily, still mark/replace |
| `sigstore/sigstore-conformance` | Sigstore conformance bundle | Apache-2.0 | Keep allowed |

## D) Current state relative to "no removal until replacement"

- Local replacement artifacts are not available yet (TDX quotes, SEV report/VCEK, own Sigstore bundle).
- Therefore, migration should remain in "staged" mode:
  - keep current non-local fixtures that are needed for test coverage;
  - keep origin metadata explicit;
  - only swap to local fixtures once artifacts are collected.

## E) Replacement plan (staged)

1. Collect local artifacts on real servers/CI:
   - `tdx-quote-1.bin`, `tdx-quote-2.bin`, `tdx-quote-3.bin`
   - `sev-attestation-report.bin`, `sev-vcek.der`
   - `sigstore-bundle.json` (+ optional `sigstore-attestation-response.json`)
2. Place artifacts into `code/katt/test/fixtures/`.
3. Regenerate collateral for your actual TDX FMSPC and refresh SEV CRLs:
   - `bun run scripts/katt/fetch-collateral.ts`
   - `bun run scripts/katt/fetch-sev-collateral.ts`
4. Update assertions to your repo/digests/measurements.
5. Run full test suite and verify no fixture fallback/skip paths.
6. Remove AGPL-associated legacy fixtures only after step 5 passes.

## F) Execution docs

- Server command runbook: `code/katt/docs/server-fixture-runbook.md`
- Full background + migration rationale: `code/katt/docs/collect-test-fixtures.md`

