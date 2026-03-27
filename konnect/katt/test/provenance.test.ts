import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { parseCertificate } from "@katt/der.js";
import { verifyCodeProvenance } from "@katt/provenance.js";
import { parseBundle } from "@katt/sigstore/bundle.js";
import { extractFulcioIdentity } from "@katt/sigstore/fulcio.js";
import SIGSTORE_TRUSTED_ROOT from "@katt/sigstore/trusted-root.js";
import type { SevVerifyResult, TdxVerifyResult } from "@katt/types.js";

if (!import.meta.dirname) throw new Error("expected import.meta.dirname");
const bundleJson = JSON.parse(readFileSync(resolve(import.meta.dirname, "fixtures/sigstore-bundle.json"), "utf-8"));

const SIGSTORE_TEST_DIGEST = "47509ed867879d9a3abc6661fa6e8806841c2a7740a399fc83cedf7036834ca0";
const parsedBundle = parseBundle(bundleJson);
const signingCert = parseCertificate(parsedBundle.signingCert);
const identity = extractFulcioIdentity(signingCert.tbs);
const SIGSTORE_TEST_REPO = identity.sourceRepoUri.replace(/^https:\/\/github\.com\//, "").replace(/\/$/, "");
const EXPECTED_SNP_MEASUREMENT = "00".repeat(48);
const EXPECTED_RTMR1 = "00".repeat(48);
const EXPECTED_RTMR2 = "00".repeat(48);

const mockSevResult: SevVerifyResult = {
  valid: true,
  measurement: EXPECTED_SNP_MEASUREMENT,
  reportData: "0".repeat(128),
  hostData: "0".repeat(64),
  chipId: "0".repeat(128),
  debug: false,
  policy: "0".repeat(16),
  version: 2,
  guestSvn: 0,
  productName: "Genoa",
};

const mockTdxResult: TdxVerifyResult = {
  valid: true,
  mrtd: "0".repeat(96),
  rtmr0: "0".repeat(96),
  rtmr1: EXPECTED_RTMR1,
  rtmr2: EXPECTED_RTMR2,
  rtmr3: "0".repeat(96),
  reportData: "0".repeat(128),
  debug: false,
  tdAttributes: "0".repeat(16),
  xfam: "0".repeat(16),
};

const opts = {
  expectedDigest: SIGSTORE_TEST_DIGEST,
  expectedRepo: SIGSTORE_TEST_REPO,
};

describe("verifyCodeProvenance", () => {
  // --- Happy path: both Sigstore and TEE valid, measurements match ---

  it("SEV-SNP with matching measurement returns valid+measurementMatch", async () => {
    const result = await verifyCodeProvenance(bundleJson, mockSevResult, opts, SIGSTORE_TRUSTED_ROOT);
    expect(result.valid).toBe(true);
    expect(result.measurementMatch).toBe(true);
    expect(result.platform).toBe("sev-snp");
  });

  it("TDX with matching rtmr1/rtmr2 returns valid+measurementMatch", async () => {
    const result = await verifyCodeProvenance(bundleJson, mockTdxResult, opts, SIGSTORE_TRUSTED_ROOT);
    expect(result.valid).toBe(true);
    expect(result.measurementMatch).toBe(true);
    expect(result.platform).toBe("tdx");
  });

  // --- Sigstore verification failure ---

  it("returns valid: false when Sigstore bundle verification fails", async () => {
    const badBundle = { ...bundleJson, mediaType: "bad" };
    const result = await verifyCodeProvenance(badBundle, mockSevResult, opts, SIGSTORE_TRUSTED_ROOT);
    expect(result.valid).toBe(false);
    expect(result.measurementMatch).toBe(false);
    expect(result.error).toBeDefined();
  });

  // --- Finding 1: measurement mismatch must produce valid: false ---

  it("SEV-SNP with wrong measurement returns valid: false", async () => {
    const wrongSev = { ...mockSevResult, measurement: "a".repeat(96) };
    const result = await verifyCodeProvenance(bundleJson, wrongSev, opts, SIGSTORE_TRUSTED_ROOT);
    expect(result.valid).toBe(false);
    expect(result.measurementMatch).toBe(false);
    expect(result.platform).toBe("sev-snp");
    expect(result.error).toMatch(/measurement/i);
  });

  it("TDX with wrong rtmr1 returns valid: false", async () => {
    const wrongTdx = { ...mockTdxResult, rtmr1: "b".repeat(96) };
    const result = await verifyCodeProvenance(bundleJson, wrongTdx, opts, SIGSTORE_TRUSTED_ROOT);
    expect(result.valid).toBe(false);
    expect(result.measurementMatch).toBe(false);
    expect(result.platform).toBe("tdx");
    expect(result.error).toMatch(/measurement/i);
  });

  it("TDX with wrong rtmr2 returns valid: false", async () => {
    const wrongTdx = { ...mockTdxResult, rtmr2: "c".repeat(96) };
    const result = await verifyCodeProvenance(bundleJson, wrongTdx, opts, SIGSTORE_TRUSTED_ROOT);
    expect(result.valid).toBe(false);
    expect(result.measurementMatch).toBe(false);
    expect(result.platform).toBe("tdx");
  });

  // --- Finding 1: teeResult.valid=false must produce valid: false ---

  it("SEV-SNP with teeResult.valid=false returns valid: false despite matching measurement", async () => {
    const failedSev = { ...mockSevResult, valid: false, error: "signature check failed" };
    const result = await verifyCodeProvenance(bundleJson, failedSev, opts, SIGSTORE_TRUSTED_ROOT);
    expect(result.valid).toBe(false);
    expect(result.measurementMatch).toBe(false);
    expect(result.error).toMatch(/TEE/i);
  });

  it("TDX with teeResult.valid=false returns valid: false despite matching RTMRs", async () => {
    const failedTdx = { ...mockTdxResult, valid: false, error: "quote verification failed" };
    const result = await verifyCodeProvenance(bundleJson, failedTdx, opts, SIGSTORE_TRUSTED_ROOT);
    expect(result.valid).toBe(false);
    expect(result.measurementMatch).toBe(false);
    expect(result.error).toMatch(/TEE/i);
  });
});
