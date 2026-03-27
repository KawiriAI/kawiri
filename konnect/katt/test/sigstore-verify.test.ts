import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { parseCertificate } from "@katt/der.js";
import { parseBundle } from "@katt/sigstore/bundle.js";
import { extractFulcioIdentity } from "@katt/sigstore/fulcio.js";
import SIGSTORE_TRUSTED_ROOT from "@katt/sigstore/trusted-root.js";
import { verifySigstoreBundle } from "@katt/sigstore/verify.js";

if (!import.meta.dirname) throw new Error("expected import.meta.dirname");
const bundleJson = JSON.parse(readFileSync(resolve(import.meta.dirname, "fixtures/sigstore-bundle.json"), "utf-8"));

const SIGSTORE_TEST_DIGEST = "47509ed867879d9a3abc6661fa6e8806841c2a7740a399fc83cedf7036834ca0";
const parsedBundle = parseBundle(bundleJson);
const signingCert = parseCertificate(parsedBundle.signingCert);
const identity = extractFulcioIdentity(signingCert.tbs);
const SIGSTORE_TEST_REPO_URI = identity.sourceRepoUri.replace(/\/$/, "");
const SIGSTORE_TEST_REPO = SIGSTORE_TEST_REPO_URI.replace(/^https:\/\/github\.com\//, "");
const SIGSTORE_TEST_REPO_OWNER = SIGSTORE_TEST_REPO.split("/")[0];
const EXPECTED_SNP_MEASUREMENT = "00".repeat(48);
const EXPECTED_RTMR1 = "00".repeat(48);
const EXPECTED_RTMR2 = "00".repeat(48);
// Extract predicate type from the fixture's DSSE payload for testing expectedPredicateType
const result_predicateType = (
  JSON.parse(new TextDecoder().decode(parsedBundle.envelope.payload)) as Record<string, unknown>
).predicateType as string;

describe("verifySigstoreBundle", () => {
  it("full verification on real bundle returns valid: true", async () => {
    const result = await verifySigstoreBundle(
      bundleJson,
      {
        expectedDigest: SIGSTORE_TEST_DIGEST,
        expectedRepo: SIGSTORE_TEST_REPO,
      },
      SIGSTORE_TRUSTED_ROOT,
    );

    expect(result.valid).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it("extracts correct SNP measurement", async () => {
    const result = await verifySigstoreBundle(
      bundleJson,
      {
        expectedDigest: SIGSTORE_TEST_DIGEST,
        expectedRepo: SIGSTORE_TEST_REPO,
      },
      SIGSTORE_TRUSTED_ROOT,
    );

    expect(result.measurements.snpMeasurement).toBe(EXPECTED_SNP_MEASUREMENT);
  });

  it("extracts correct TDX RTMR1 and RTMR2", async () => {
    const result = await verifySigstoreBundle(
      bundleJson,
      {
        expectedDigest: SIGSTORE_TEST_DIGEST,
        expectedRepo: SIGSTORE_TEST_REPO,
      },
      SIGSTORE_TRUSTED_ROOT,
    );

    expect(result.measurements.tdxRtmr1).toBe(EXPECTED_RTMR1);
    expect(result.measurements.tdxRtmr2).toBe(EXPECTED_RTMR2);
  });

  it("populates correct identity fields", async () => {
    const result = await verifySigstoreBundle(
      bundleJson,
      {
        expectedDigest: SIGSTORE_TEST_DIGEST,
        expectedRepo: SIGSTORE_TEST_REPO,
      },
      SIGSTORE_TRUSTED_ROOT,
    );

    expect(result.oidcIssuer).toBe("https://token.actions.githubusercontent.com");
    expect(result.sourceRepo.endsWith(`/${SIGSTORE_TEST_REPO}`)).toBe(true);
    expect(result.workflowRef).toMatch(/^refs\/tags\//);
  });

  it("logIndex is a positive number", async () => {
    const result = await verifySigstoreBundle(
      bundleJson,
      {
        expectedDigest: SIGSTORE_TEST_DIGEST,
        expectedRepo: SIGSTORE_TEST_REPO,
      },
      SIGSTORE_TRUSTED_ROOT,
    );

    expect(result.logIndex).toBeGreaterThan(0);
    expect(result.integratedTime).toBeGreaterThan(0);
  });

  it("has correct predicate type", async () => {
    const result = await verifySigstoreBundle(
      bundleJson,
      {
        expectedDigest: SIGSTORE_TEST_DIGEST,
        expectedRepo: SIGSTORE_TEST_REPO,
      },
      SIGSTORE_TRUSTED_ROOT,
    );

    expect(result.predicateType).toBe("https://kawiri.ai/predicate/cvm-measurements/v1");
  });

  it("rejects wrong expectedPredicateType with PAYLOAD_ERROR", async () => {
    const result = await verifySigstoreBundle(
      bundleJson,
      {
        expectedDigest: SIGSTORE_TEST_DIGEST,
        expectedRepo: SIGSTORE_TEST_REPO,
        expectedPredicateType: "https://example.com/wrong/type/v1",
      },
      SIGSTORE_TRUSTED_ROOT,
    );
    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe("PAYLOAD_ERROR");
    expect(result.error).toMatch(/predicate type/i);
  });

  it("passes when expectedPredicateType matches", async () => {
    const result = await verifySigstoreBundle(
      bundleJson,
      {
        expectedDigest: SIGSTORE_TEST_DIGEST,
        expectedRepo: SIGSTORE_TEST_REPO,
        expectedPredicateType: result_predicateType,
      },
      SIGSTORE_TRUSTED_ROOT,
    );
    expect(result.valid).toBe(true);
  });

  it("rejects wrong expectedDigest with PAYLOAD_ERROR", async () => {
    const result = await verifySigstoreBundle(
      bundleJson,
      {
        expectedDigest: `aaaa${SIGSTORE_TEST_DIGEST.slice(4)}`,
        expectedRepo: SIGSTORE_TEST_REPO,
      },
      SIGSTORE_TRUSTED_ROOT,
    );
    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe("PAYLOAD_ERROR");
    expect(result.error).toMatch(/digest/i);
  });

  it("rejects wrong expectedRepo with POLICY_ERROR", async () => {
    const result = await verifySigstoreBundle(
      bundleJson,
      {
        expectedDigest: SIGSTORE_TEST_DIGEST,
        expectedRepo: "wrong/repo",
      },
      SIGSTORE_TRUSTED_ROOT,
    );
    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe("POLICY_ERROR");
    expect(result.error).toMatch(/repo/i);
  });

  it("rejects substring-only repo match with POLICY_ERROR", async () => {
    const result = await verifySigstoreBundle(
      bundleJson,
      {
        expectedDigest: SIGSTORE_TEST_DIGEST,
        expectedRepo: "deepseek-r1-0528", // substring, not full owner/repo
      },
      SIGSTORE_TRUSTED_ROOT,
    );
    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe("POLICY_ERROR");
  });

  it("rejects prefix-only repo match with POLICY_ERROR", async () => {
    const result = await verifySigstoreBundle(
      bundleJson,
      {
        expectedDigest: SIGSTORE_TEST_DIGEST,
        expectedRepo: `${SIGSTORE_TEST_REPO_OWNER}/partial`, // prefix, not full owner/repo
      },
      SIGSTORE_TRUSTED_ROOT,
    );
    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe("POLICY_ERROR");
  });

  it("rejects corrupted signature in bundle", async () => {
    const corruptedBundle = JSON.parse(JSON.stringify(bundleJson));
    // Corrupt the signature
    const origSig = corruptedBundle.dsseEnvelope.signatures[0].sig;
    corruptedBundle.dsseEnvelope.signatures[0].sig = `AAAA${origSig.slice(4)}`;

    const result = await verifySigstoreBundle(
      corruptedBundle,
      {
        expectedDigest: SIGSTORE_TEST_DIGEST,
        expectedRepo: SIGSTORE_TEST_REPO,
      },
      SIGSTORE_TRUSTED_ROOT,
    );
    expect(result.valid).toBe(false);
    expect(result.error).toBeDefined();
  });

  it("rejects corrupted cert in bundle", async () => {
    const corruptedBundle = JSON.parse(JSON.stringify(bundleJson));
    // Corrupt the certificate
    corruptedBundle.verificationMaterial.certificate.rawBytes = "AAAA";

    const result = await verifySigstoreBundle(
      corruptedBundle,
      {
        expectedDigest: SIGSTORE_TEST_DIGEST,
        expectedRepo: SIGSTORE_TEST_REPO,
      },
      SIGSTORE_TRUSTED_ROOT,
    );
    expect(result.valid).toBe(false);
    expect(result.error).toBeDefined();
  });

  it("rejects when integratedTime is outside signing cert validity window", async () => {
    const modifiedBundle = JSON.parse(JSON.stringify(bundleJson));
    // Set integratedTime to year 2030 — far outside short-lived Fulcio cert validity
    modifiedBundle.verificationMaterial.tlogEntries[0].integratedTime = "1893456000";

    const result = await verifySigstoreBundle(
      modifiedBundle,
      {
        expectedDigest: SIGSTORE_TEST_DIGEST,
        expectedRepo: SIGSTORE_TEST_REPO,
      },
      SIGSTORE_TRUSTED_ROOT,
    );
    expect(result.valid).toBe(false);
    // Rejected either by tlog key validFor (TLOG_ERROR) or cert validity (CERTIFICATE_ERROR)
    expect(result.errorCode).toBeDefined();
    expect(["TLOG_ERROR", "CERTIFICATE_ERROR"]).toContain(result.errorCode as string);
  });

  it("rejects when integratedTime is before signing cert validity window", async () => {
    const modifiedBundle = JSON.parse(JSON.stringify(bundleJson));
    // Set integratedTime to year 2020 — before any Fulcio cert or tlog key was valid
    modifiedBundle.verificationMaterial.tlogEntries[0].integratedTime = "1577836800";

    const result = await verifySigstoreBundle(
      modifiedBundle,
      {
        expectedDigest: SIGSTORE_TEST_DIGEST,
        expectedRepo: SIGSTORE_TEST_REPO,
      },
      SIGSTORE_TRUSTED_ROOT,
    );
    expect(result.valid).toBe(false);
    // Rejected either by tlog key validFor (TLOG_ERROR) or cert validity (CERTIFICATE_ERROR)
    expect(result.errorCode).toBeDefined();
    expect(["TLOG_ERROR", "CERTIFICATE_ERROR"]).toContain(result.errorCode as string);
  });

  it("rejects wrong workflow ref pattern with POLICY_ERROR", async () => {
    const result = await verifySigstoreBundle(
      bundleJson,
      {
        expectedDigest: SIGSTORE_TEST_DIGEST,
        expectedRepo: SIGSTORE_TEST_REPO,
        workflowRefPattern: /^refs\/heads\//, // real bundle uses refs/tags/
      },
      SIGSTORE_TRUSTED_ROOT,
    );
    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe("POLICY_ERROR");
    expect(result.error).toMatch(/workflow ref/i);
  });

  it("rejects when tlogThreshold exceeds available entries", async () => {
    const result = await verifySigstoreBundle(
      bundleJson,
      {
        expectedDigest: SIGSTORE_TEST_DIGEST,
        expectedRepo: SIGSTORE_TEST_REPO,
        tlogThreshold: 2,
      },
      SIGSTORE_TRUSTED_ROOT,
    );
    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe("TLOG_ERROR");
    expect(result.error).toMatch(/tlog/i);
  });

  it("passes with explicit tlogThreshold=1", async () => {
    const result = await verifySigstoreBundle(
      bundleJson,
      {
        expectedDigest: SIGSTORE_TEST_DIGEST,
        expectedRepo: SIGSTORE_TEST_REPO,
        tlogThreshold: 1,
      },
      SIGSTORE_TRUSTED_ROOT,
    );
    expect(result.valid).toBe(true);
  });

  it("rejects null bundle input", async () => {
    const result = await verifySigstoreBundle(
      null,
      {
        expectedDigest: SIGSTORE_TEST_DIGEST,
        expectedRepo: SIGSTORE_TEST_REPO,
      },
      SIGSTORE_TRUSTED_ROOT,
    );
    expect(result.valid).toBe(false);
    expect(result.error).toBeDefined();
  });

  it("rejects empty object as bundle", async () => {
    const result = await verifySigstoreBundle(
      {},
      {
        expectedDigest: SIGSTORE_TEST_DIGEST,
        expectedRepo: SIGSTORE_TEST_REPO,
      },
      SIGSTORE_TRUSTED_ROOT,
    );
    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe("BUNDLE_PARSE_ERROR");
  });

  it("populates errorCode for all failure cases", async () => {
    // Test that errorCode is always set on failure
    const digestResult = await verifySigstoreBundle(
      bundleJson,
      {
        expectedDigest: "wrong",
        expectedRepo: SIGSTORE_TEST_REPO,
      },
      SIGSTORE_TRUSTED_ROOT,
    );
    expect(digestResult.valid).toBe(false);
    expect(digestResult.errorCode).toBeDefined();

    const repoResult = await verifySigstoreBundle(
      bundleJson,
      {
        expectedDigest: SIGSTORE_TEST_DIGEST,
        expectedRepo: "wrong",
      },
      SIGSTORE_TRUSTED_ROOT,
    );
    expect(repoResult.valid).toBe(false);
    expect(repoResult.errorCode).toBeDefined();
  });

  // --- Finding 6: repo match must use exact URI path, not suffix ---

  it("accepts full URI as expectedRepo", async () => {
    const result = await verifySigstoreBundle(
      bundleJson,
      {
        expectedDigest: SIGSTORE_TEST_DIGEST,
        expectedRepo: SIGSTORE_TEST_REPO_URI,
      },
      SIGSTORE_TRUSTED_ROOT,
    );
    expect(result.valid).toBe(true);
  });

  it("rejects repo with extra path prefix that would match suffix", async () => {
    // 'x/<owner>/<repo>' is not a valid owner/repo
    // — must not match just because the URI ends with it
    const result = await verifySigstoreBundle(
      bundleJson,
      {
        expectedDigest: SIGSTORE_TEST_DIGEST,
        expectedRepo: `x/${SIGSTORE_TEST_REPO}`,
      },
      SIGSTORE_TRUSTED_ROOT,
    );
    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe("POLICY_ERROR");
  });

  // --- Finding 7: threshold=0 must not bypass verification ---

  it("rejects tlogThreshold=0 (would bypass transparency log)", async () => {
    const result = await verifySigstoreBundle(
      bundleJson,
      {
        expectedDigest: SIGSTORE_TEST_DIGEST,
        expectedRepo: SIGSTORE_TEST_REPO,
        tlogThreshold: 0,
      },
      SIGSTORE_TRUSTED_ROOT,
    );
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/threshold/i);
  });

  it("rejects ctlogThreshold=0 (would bypass CT log)", async () => {
    const result = await verifySigstoreBundle(
      bundleJson,
      {
        expectedDigest: SIGSTORE_TEST_DIGEST,
        expectedRepo: SIGSTORE_TEST_REPO,
        ctlogThreshold: 0,
      },
      SIGSTORE_TRUSTED_ROOT,
    );
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/threshold/i);
  });

  it("rejects timestampThreshold=0 (would bypass timestamp requirement)", async () => {
    const result = await verifySigstoreBundle(
      bundleJson,
      {
        expectedDigest: SIGSTORE_TEST_DIGEST,
        expectedRepo: SIGSTORE_TEST_REPO,
        timestampThreshold: 0,
      },
      SIGSTORE_TRUSTED_ROOT,
    );
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/threshold/i);
  });

  it("rejects negative tlogThreshold", async () => {
    const result = await verifySigstoreBundle(
      bundleJson,
      {
        expectedDigest: SIGSTORE_TEST_DIGEST,
        expectedRepo: SIGSTORE_TEST_REPO,
        tlogThreshold: -1,
      },
      SIGSTORE_TRUSTED_ROOT,
    );
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/threshold/i);
  });

  // --- Malformed integratedTime rejection ---

  it("rejects NaN integratedTime with BUNDLE_PARSE_ERROR", async () => {
    const modifiedBundle = JSON.parse(JSON.stringify(bundleJson));
    modifiedBundle.verificationMaterial.tlogEntries[0].integratedTime = "not-a-number";
    const result = await verifySigstoreBundle(
      modifiedBundle,
      {
        expectedDigest: SIGSTORE_TEST_DIGEST,
        expectedRepo: SIGSTORE_TEST_REPO,
      },
      SIGSTORE_TRUSTED_ROOT,
    );
    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe("BUNDLE_PARSE_ERROR");
    expect(result.error).toMatch(/integratedTime/i);
  });

  it("rejects Infinity integratedTime with BUNDLE_PARSE_ERROR", async () => {
    const modifiedBundle = JSON.parse(JSON.stringify(bundleJson));
    modifiedBundle.verificationMaterial.tlogEntries[0].integratedTime = "Infinity";
    const result = await verifySigstoreBundle(
      modifiedBundle,
      {
        expectedDigest: SIGSTORE_TEST_DIGEST,
        expectedRepo: SIGSTORE_TEST_REPO,
      },
      SIGSTORE_TRUSTED_ROOT,
    );
    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe("BUNDLE_PARSE_ERROR");
    expect(result.error).toMatch(/integratedTime/i);
  });

  it("rejects zero integratedTime with BUNDLE_PARSE_ERROR", async () => {
    const modifiedBundle = JSON.parse(JSON.stringify(bundleJson));
    modifiedBundle.verificationMaterial.tlogEntries[0].integratedTime = "0";
    const result = await verifySigstoreBundle(
      modifiedBundle,
      {
        expectedDigest: SIGSTORE_TEST_DIGEST,
        expectedRepo: SIGSTORE_TEST_REPO,
      },
      SIGSTORE_TRUSTED_ROOT,
    );
    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe("BUNDLE_PARSE_ERROR");
    expect(result.error).toMatch(/integratedTime/i);
  });

  it("rejects negative integratedTime with BUNDLE_PARSE_ERROR", async () => {
    const modifiedBundle = JSON.parse(JSON.stringify(bundleJson));
    modifiedBundle.verificationMaterial.tlogEntries[0].integratedTime = "-100";
    const result = await verifySigstoreBundle(
      modifiedBundle,
      {
        expectedDigest: SIGSTORE_TEST_DIGEST,
        expectedRepo: SIGSTORE_TEST_REPO,
      },
      SIGSTORE_TRUSTED_ROOT,
    );
    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe("BUNDLE_PARSE_ERROR");
    expect(result.error).toMatch(/integratedTime/i);
  });

  // --- Inclusion proof consistency adversarial tests ---

  it("rejects when inclusionProof.logIndex is tampered (consistency check)", async () => {
    const modifiedBundle = JSON.parse(JSON.stringify(bundleJson));
    const entry = modifiedBundle.verificationMaterial.tlogEntries[0];
    // Corrupt SET to force fallback to inclusion proof
    if (entry.inclusionPromise) {
      entry.inclusionPromise.signedEntryTimestamp = "AAAA";
    }
    // Tamper with inclusion proof logIndex to trigger consistency check
    if (entry.inclusionProof) {
      entry.inclusionProof.logIndex = String(Number(entry.inclusionProof.logIndex ?? entry.logIndex) + 999);
    }
    const result = await verifySigstoreBundle(
      modifiedBundle,
      {
        expectedDigest: SIGSTORE_TEST_DIGEST,
        expectedRepo: SIGSTORE_TEST_REPO,
      },
      SIGSTORE_TRUSTED_ROOT,
    );
    expect(result.valid).toBe(false);
    expect(result.error).toBeDefined();
  });

  it("rejects when inclusionProof.treeSize is tampered", async () => {
    const modifiedBundle = JSON.parse(JSON.stringify(bundleJson));
    const entry = modifiedBundle.verificationMaterial.tlogEntries[0];
    // Corrupt SET to force fallback to inclusion proof
    if (entry.inclusionPromise) {
      entry.inclusionPromise.signedEntryTimestamp = "AAAA";
    }
    // Tamper with treeSize
    if (entry.inclusionProof) {
      entry.inclusionProof.treeSize = "1";
    }
    const result = await verifySigstoreBundle(
      modifiedBundle,
      {
        expectedDigest: SIGSTORE_TEST_DIGEST,
        expectedRepo: SIGSTORE_TEST_REPO,
      },
      SIGSTORE_TRUSTED_ROOT,
    );
    expect(result.valid).toBe(false);
    expect(result.error).toBeDefined();
  });

  it("rejects when inclusionProof.rootHash is tampered", async () => {
    const modifiedBundle = JSON.parse(JSON.stringify(bundleJson));
    const entry = modifiedBundle.verificationMaterial.tlogEntries[0];
    // Corrupt SET to force fallback to inclusion proof
    if (entry.inclusionPromise) {
      entry.inclusionPromise.signedEntryTimestamp = "AAAA";
    }
    // Tamper with rootHash
    if (entry.inclusionProof) {
      entry.inclusionProof.rootHash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    }
    const result = await verifySigstoreBundle(
      modifiedBundle,
      {
        expectedDigest: SIGSTORE_TEST_DIGEST,
        expectedRepo: SIGSTORE_TEST_REPO,
      },
      SIGSTORE_TRUSTED_ROOT,
    );
    expect(result.valid).toBe(false);
    expect(result.error).toBeDefined();
  });
});
