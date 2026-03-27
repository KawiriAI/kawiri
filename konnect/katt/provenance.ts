import type { ProvenanceVerifyResult, SigstoreVerifyOptions, TrustedRoot } from "./sigstore/types.ts";
import { verifySigstoreBundle } from "./sigstore/verify.ts";
import type { SevVerifyResult, TdxVerifyResult } from "./types.ts";

/**
 * Verify code provenance: Sigstore bundle + TEE attestation + measurement match.
 *
 * Returns `valid: true` ONLY when all three conditions hold:
 * 1. Sigstore bundle verification passes
 * 2. TEE attestation passed (`teeResult.valid === true`)
 * 3. Measurements from Sigstore predicate match TEE attestation
 *
 * Callers should check `result.valid` as the single authoritative gate.
 * `result.measurementMatch` provides additional detail.
 */
export async function verifyCodeProvenance(
  bundle: unknown,
  teeResult: TdxVerifyResult | SevVerifyResult,
  opts: SigstoreVerifyOptions,
  trustedRoot?: TrustedRoot,
): Promise<ProvenanceVerifyResult> {
  const platform = isSevResult(teeResult) ? ("sev-snp" as const) : ("tdx" as const);

  const sigResult = await verifySigstoreBundle(bundle, opts, trustedRoot);

  if (!sigResult.valid) {
    return { ...sigResult, measurementMatch: false, platform };
  }

  // TEE attestation must have passed — measurements are only meaningful
  // when the hardware has cryptographically attested them.
  if (!teeResult.valid) {
    return {
      ...sigResult,
      valid: false,
      measurementMatch: false,
      platform,
      error: `TEE attestation failed: ${teeResult.error ?? "unknown error"}`,
      errorCode: "PROVENANCE_ERROR",
    };
  }

  // Compare measurements
  if (isSevResult(teeResult)) {
    const match = sigResult.measurements.snpMeasurement === teeResult.measurement;
    if (!match) {
      return {
        ...sigResult,
        valid: false,
        measurementMatch: false,
        platform,
        error: `SEV-SNP measurement mismatch: Sigstore predicate "${sigResult.measurements.snpMeasurement ?? "(none)"}", TEE report "${teeResult.measurement}"`,
        errorCode: "PROVENANCE_ERROR",
      };
    }
    return { ...sigResult, measurementMatch: true, platform };
  } else {
    const rtmr1Match = sigResult.measurements.tdxRtmr1 === teeResult.rtmr1;
    const rtmr2Match = sigResult.measurements.tdxRtmr2 === teeResult.rtmr2;
    if (!rtmr1Match || !rtmr2Match) {
      return {
        ...sigResult,
        valid: false,
        measurementMatch: false,
        platform,
        error: `TDX measurement mismatch: RTMR1 ${rtmr1Match ? "ok" : "differs"}, RTMR2 ${rtmr2Match ? "ok" : "differs"}`,
        errorCode: "PROVENANCE_ERROR",
      };
    }
    return { ...sigResult, measurementMatch: true, platform };
  }
}

function isSevResult(result: TdxVerifyResult | SevVerifyResult): result is SevVerifyResult {
  return "measurement" in result;
}
