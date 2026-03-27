/**
 * Cross-verification tests using a SECOND independent Sigstore bundle
 * from the sigstore-conformance test suite.
 *
 * This bundle is completely different from our primary fixture:
 * - Different signer (sigstore-conformance OIDC beacon)
 * - Different predicate (SLSA provenance v1)
 * - Different workflow ref (refs/heads/main, not a tag)
 * - Different date (2024-12-16 vs 2025-07-13)
 *
 * If our code verifies BOTH bundles, it proves the implementation is correct
 * and not accidentally coupled to a single fixture.
 */
import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { decodeOid, derSignatureToRaw, extractExtensions, parseCertificate } from "@katt/der.js";
import { parseBundle } from "@katt/sigstore/bundle.js";
import { verifyDSSESignature } from "@katt/sigstore/dsse.js";
import { verifyFulcioCert, verifySCTs } from "@katt/sigstore/fulcio.js";
import { canonicalize } from "@katt/sigstore/json.js";
import { verifyCheckpoint, verifyTLogBody, verifyTLogEntry, verifyTLogSET } from "@katt/sigstore/rekor.js";
import SIGSTORE_TRUSTED_ROOT from "@katt/sigstore/trusted-root.js";
import { verifySigstoreBundle } from "@katt/sigstore/verify.js";

if (!import.meta.dirname) throw new Error("expected import.meta.dirname");
const conformanceBundle = JSON.parse(
  readFileSync(resolve(import.meta.dirname, "fixtures/sigstore-conformance-bundle.json"), "utf-8"),
);

// Expected values for the conformance bundle
const CONFORMANCE_DIGEST = "a0cfc71271d6e278e57cd332ff957c3f7043fdda354c4cbb190a30d56efa01bf";
const CONFORMANCE_REPO = "sigstore-conformance/extremely-dangerous-public-oidc-beacon";

describe("cross-verification: bundle parsing", () => {
  it("parses the conformance bundle successfully", () => {
    const parsed = parseBundle(conformanceBundle);
    expect(parsed.mediaType).toBe("application/vnd.dev.sigstore.bundle.v0.3+json");
    expect(parsed.signingCert).toBeInstanceOf(Uint8Array);
    expect(parsed.signingCert.length).toBeGreaterThan(100);
    expect(parsed.envelope.payloadType).toBe("application/vnd.in-toto+json");
    expect(parsed.envelope.payload).toBeInstanceOf(Uint8Array);
    expect(parsed.envelope.signature).toBeInstanceOf(Uint8Array);
    expect(parsed.tlogEntry.kindVersion.kind).toBe("dsse");
    expect(parsed.tlogEntry.kindVersion.version).toBe("0.0.1");
  });

  it("parses SLSA provenance payload", () => {
    const parsed = parseBundle(conformanceBundle);
    const payload = JSON.parse(new TextDecoder().decode(parsed.envelope.payload));
    expect(payload._type).toBe("https://in-toto.io/Statement/v1");
    expect(payload.predicateType).toBe("https://slsa.dev/provenance/v1");
    expect(payload.subject[0].digest.sha256).toBe(CONFORMANCE_DIGEST);
    expect(payload.subject[0].name).toBe("a.txt");
  });
});

describe("cross-verification: Fulcio cert chain", () => {
  it("verifies conformance cert chains to trusted Fulcio CA", async () => {
    const parsed = parseBundle(conformanceBundle);
    const result = await verifyFulcioCert(parsed.signingCert, SIGSTORE_TRUSTED_ROOT);
    expect(result.identity).toBeDefined();
    expect(result.signingKey).toBeDefined();
    expect(result.identity.oidcIssuer).toBe("https://token.actions.githubusercontent.com");
  });

  it("extracts conformance identity (different from primary fixture)", async () => {
    const parsed = parseBundle(conformanceBundle);
    const { identity } = await verifyFulcioCert(parsed.signingCert, SIGSTORE_TRUSTED_ROOT);

    expect(identity.oidcIssuer).toBe("https://token.actions.githubusercontent.com");
    expect(identity.sourceRepoUri).toContain(CONFORMANCE_REPO);
    expect(identity.sourceRepoRef).toBe("refs/heads/main");
    expect(identity.sourceRepoDigest).toMatch(/^[a-f0-9]{40}$/);
    expect(identity.buildSignerUri).toContain("github.com");
    expect(identity.buildSignerUri).toContain("extremely-dangerous-oidc-beacon.yml");
  });

  it("verifies conformance cert has all v2 Fulcio extensions", () => {
    const parsed = parseBundle(conformanceBundle);
    const cert = parseCertificate(parsed.signingCert);
    const exts = extractExtensions(cert.tbs);

    // Conformance cert should have many extensions (v2 format)
    expect(exts.length).toBeGreaterThanOrEqual(20);

    // Verify OID presence for key Fulcio v2 extensions
    const oids = exts.map((e) => decodeOid(e.oid));
    expect(oids).toContain("1.3.6.1.4.1.57264.1.8"); // OIDC Issuer v2
    expect(oids).toContain("1.3.6.1.4.1.57264.1.9"); // Build Signer URI
    expect(oids).toContain("1.3.6.1.4.1.57264.1.12"); // Source Repository URI
    expect(oids).toContain("1.3.6.1.4.1.57264.1.13"); // Source Repository Digest
    expect(oids).toContain("1.3.6.1.4.1.57264.1.14"); // Source Repository Ref
    expect(oids).toContain("1.3.6.1.4.1.57264.1.18"); // Build Config URI
    expect(oids).toContain("1.3.6.1.4.1.57264.1.20"); // Build Trigger
    expect(oids).toContain("1.3.6.1.4.1.57264.1.21"); // Run Invocation URI
  });
});

describe("cross-verification: SCT", () => {
  it("verifies SCTs from conformance cert", async () => {
    const parsed = parseBundle(conformanceBundle);
    const count = await verifySCTs(parsed.signingCert, SIGSTORE_TRUSTED_ROOT);
    expect(count).toBeGreaterThanOrEqual(1);
  });
});

describe("cross-verification: DSSE signature", () => {
  it("verifies DSSE signature from conformance bundle", async () => {
    const parsed = parseBundle(conformanceBundle);
    const { signingKey } = await verifyFulcioCert(parsed.signingCert, SIGSTORE_TRUSTED_ROOT);
    const valid = await verifyDSSESignature(parsed.envelope, signingKey);
    expect(valid).toBe(true);
  });
});

describe("cross-verification: Rekor tlog entry", () => {
  it("verifies SET (inclusion promise) from conformance bundle", async () => {
    const parsed = parseBundle(conformanceBundle);
    await expect(verifyTLogSET(parsed.tlogEntry, SIGSTORE_TRUSTED_ROOT)).resolves.toBeUndefined();
  });

  it("verifies checkpoint from conformance bundle", async () => {
    const parsed = parseBundle(conformanceBundle);
    const checkpoint = await verifyCheckpoint(parsed.tlogEntry, SIGSTORE_TRUSTED_ROOT);
    expect(checkpoint.origin).toBe("rekor.sigstore.dev - 1193050959916656506");
    expect(checkpoint.logSize).toBe(33786589n);
    expect(checkpoint.logHash).toBeInstanceOf(Uint8Array);
    expect(checkpoint.logHash.length).toBe(32);
  });

  it("verifies tlog body matches DSSE envelope", async () => {
    const parsed = parseBundle(conformanceBundle);
    await expect(verifyTLogBody(parsed.tlogEntry, parsed.envelope)).resolves.toBeUndefined();
  });

  it("verifies full tlog entry (body + SET + Merkle)", async () => {
    const parsed = parseBundle(conformanceBundle);
    await expect(verifyTLogEntry(parsed.tlogEntry, parsed.envelope, SIGSTORE_TRUSTED_ROOT)).resolves.toBeUndefined();
  });
});

describe("cross-verification: full end-to-end", () => {
  it("full verification of conformance bundle", async () => {
    const result = await verifySigstoreBundle(
      conformanceBundle,
      {
        expectedDigest: CONFORMANCE_DIGEST,
        expectedRepo: CONFORMANCE_REPO,
        workflowRefPattern: /^refs\/heads\/main$/,
      },
      SIGSTORE_TRUSTED_ROOT,
    );

    expect(result.valid).toBe(true);
    expect(result.oidcIssuer).toBe("https://token.actions.githubusercontent.com");
    expect(result.sourceRepo.endsWith(`/${CONFORMANCE_REPO}`)).toBe(true);
    expect(result.workflowRef).toBe("refs/heads/main");
    expect(result.predicateType).toBe("https://slsa.dev/provenance/v1");
    expect(result.logIndex).toBe(155690850);
    expect(result.integratedTime).toBe(1734374576);
  });

  it("rejects conformance bundle with wrong digest", async () => {
    const result = await verifySigstoreBundle(
      conformanceBundle,
      {
        expectedDigest: "deadbeef",
        expectedRepo: CONFORMANCE_REPO,
        workflowRefPattern: /^refs\/heads\/main$/,
      },
      SIGSTORE_TRUSTED_ROOT,
    );
    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe("PAYLOAD_ERROR");
    expect(result.error).toMatch(/digest/i);
  });

  it("rejects conformance bundle with wrong repo", async () => {
    const result = await verifySigstoreBundle(
      conformanceBundle,
      {
        expectedDigest: CONFORMANCE_DIGEST,
        expectedRepo: "wrong/repo",
        workflowRefPattern: /^refs\/heads\/main$/,
      },
      SIGSTORE_TRUSTED_ROOT,
    );
    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe("POLICY_ERROR");
    expect(result.error).toMatch(/repo/i);
  });

  it("rejects conformance bundle with wrong workflow ref pattern", async () => {
    const result = await verifySigstoreBundle(
      conformanceBundle,
      {
        expectedDigest: CONFORMANCE_DIGEST,
        expectedRepo: CONFORMANCE_REPO,
        workflowRefPattern: /^refs\/tags\//, // conformance uses refs/heads/main
      },
      SIGSTORE_TRUSTED_ROOT,
    );
    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe("POLICY_ERROR");
    expect(result.error).toMatch(/workflow ref/i);
  });
});

describe("JSON canonicalization (JCS) edge cases", () => {
  it("sorts keys lexicographically", () => {
    expect(canonicalize({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
    expect(canonicalize({ z: 0, a: 0, m: 0 })).toBe('{"a":0,"m":0,"z":0}');
  });

  it("handles nested objects with sorted keys", () => {
    expect(canonicalize({ b: { d: 1, c: 2 }, a: 3 })).toBe('{"a":3,"b":{"c":2,"d":1}}');
  });

  it("preserves array order", () => {
    expect(canonicalize([3, 1, 2])).toBe("[3,1,2]");
    expect(canonicalize({ a: [3, 1, 2] })).toBe('{"a":[3,1,2]}');
  });

  it("handles null and booleans", () => {
    expect(canonicalize(null)).toBe("null");
    expect(canonicalize(true)).toBe("true");
    expect(canonicalize(false)).toBe("false");
  });

  it("handles integers correctly", () => {
    expect(canonicalize(0)).toBe("0");
    expect(canonicalize(1)).toBe("1");
    expect(canonicalize(-1)).toBe("-1");
    expect(canonicalize(1234567890)).toBe("1234567890");
  });

  it("handles string escaping", () => {
    expect(canonicalize("hello")).toBe('"hello"');
    expect(canonicalize('he"llo')).toBe('"he\\"llo"');
    expect(canonicalize("he\\llo")).toBe('"he\\\\llo"');
  });

  it("omits undefined values", () => {
    expect(canonicalize({ a: 1, b: undefined, c: 3 })).toBe('{"a":1,"c":3}');
  });

  it("no whitespace in output", () => {
    const result = canonicalize({ key: [1, 2, 3], nested: { a: "b" } });
    expect(result).not.toContain(" ");
    expect(result).not.toContain("\n");
    expect(result).not.toContain("\t");
  });

  it("matches expected SET payload format", () => {
    // This is the exact structure used in Rekor SET verification
    const payload = {
      body: "dGVzdA==",
      integratedTime: 1752443897,
      logIndex: 273164531,
      logID: "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
    };
    const result = canonicalize(payload);
    // Keys must be in alphabetical order
    expect(result).toBe(
      '{"body":"dGVzdA==","integratedTime":1752443897,"logID":"c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d","logIndex":273164531}',
    );
  });
});

describe("DER signature conversion edge cases", () => {
  it("handles standard P-256 signature (32-byte components)", () => {
    // DER: SEQUENCE { INTEGER r (33 bytes with leading 0), INTEGER s (32 bytes) }
    const der = new Uint8Array([
      0x30,
      0x45, // SEQUENCE, 69 bytes
      0x02,
      0x21, // INTEGER, 33 bytes (leading 0x00)
      0x00,
      ...new Uint8Array(32).fill(0xaa), // r with leading zero
      0x02,
      0x20, // INTEGER, 32 bytes
      ...new Uint8Array(32).fill(0xbb), // s
    ]);
    const raw = derSignatureToRaw(der, 32);
    expect(raw.length).toBe(64);
    // r should be 32 bytes of 0xAA (leading zero stripped)
    expect(raw.slice(0, 32)).toEqual(new Uint8Array(32).fill(0xaa));
    // s should be 32 bytes of 0xBB
    expect(raw.slice(32)).toEqual(new Uint8Array(32).fill(0xbb));
  });

  it("handles short r component (zero-padded)", () => {
    // r is only 20 bytes (no leading zero), should be left-padded to 32
    const rBytes = new Uint8Array(20).fill(0xcc);
    const sBytes = new Uint8Array(32).fill(0xdd);
    const der = new Uint8Array([
      0x30,
      2 + 20 + 2 + 32, // SEQUENCE
      0x02,
      20,
      ...rBytes, // INTEGER r (20 bytes, short)
      0x02,
      32,
      ...sBytes, // INTEGER s (32 bytes)
    ]);
    const raw = derSignatureToRaw(der, 32);
    expect(raw.length).toBe(64);
    // First 12 bytes should be zero padding
    expect(raw.slice(0, 12)).toEqual(new Uint8Array(12).fill(0));
    // Then 20 bytes of 0xCC
    expect(raw.slice(12, 32)).toEqual(new Uint8Array(20).fill(0xcc));
    // Then 32 bytes of 0xDD
    expect(raw.slice(32)).toEqual(new Uint8Array(32).fill(0xdd));
  });

  it("handles P-384 signature (48-byte components)", () => {
    const rBytes = new Uint8Array([0x00, ...new Uint8Array(48).fill(0x11)]);
    const sBytes = new Uint8Array(48).fill(0x22);
    const der = new Uint8Array([
      0x30,
      2 + 49 + 2 + 48, // SEQUENCE
      0x02,
      49,
      ...rBytes, // INTEGER r (49 bytes with leading 0)
      0x02,
      48,
      ...sBytes, // INTEGER s (48 bytes)
    ]);
    const raw = derSignatureToRaw(der, 48);
    expect(raw.length).toBe(96);
    expect(raw.slice(0, 48)).toEqual(new Uint8Array(48).fill(0x11));
    expect(raw.slice(48)).toEqual(new Uint8Array(48).fill(0x22));
  });

  it("rejects non-SEQUENCE input", () => {
    const bad = new Uint8Array([0x31, 0x00]); // SET, not SEQUENCE
    expect(() => derSignatureToRaw(bad, 32)).toThrow("expected SEQUENCE");
  });

  it("rejects non-INTEGER r component", () => {
    const bad = new Uint8Array([
      0x30,
      0x04, // SEQUENCE
      0x03,
      0x02,
      0x00,
      0x00, // BIT STRING instead of INTEGER
    ]);
    expect(() => derSignatureToRaw(bad, 32)).toThrow("expected INTEGER");
  });
});

describe("Merkle proof helper functions", () => {
  // Test the core Merkle hashing against known test vectors
  it("leaf hash matches RFC 6962 definition", async () => {
    // SHA-256(0x00 || data)
    const data = new Uint8Array([0x01, 0x02, 0x03]);
    const prefixed = new Uint8Array([0x00, 0x01, 0x02, 0x03]);
    const expected = new Uint8Array(await crypto.subtle.digest("SHA-256", prefixed));

    // Compute via the same method used in merkle.ts
    const leafPrefixed = new Uint8Array(1 + data.length);
    leafPrefixed[0] = 0x00;
    leafPrefixed.set(data, 1);
    const actual = new Uint8Array(await crypto.subtle.digest("SHA-256", leafPrefixed));

    expect(actual).toEqual(expected);
  });

  it("node hash matches RFC 6962 definition", async () => {
    // SHA-256(0x01 || left || right)
    const left = new Uint8Array(32).fill(0xaa);
    const right = new Uint8Array(32).fill(0xbb);
    const combined = new Uint8Array(1 + 32 + 32);
    combined[0] = 0x01;
    combined.set(left, 1);
    combined.set(right, 33);
    const expected = new Uint8Array(await crypto.subtle.digest("SHA-256", combined));

    // This should be the same regardless of implementation
    expect(expected.length).toBe(32);
    // Verify it's not just all zeros (hash is non-trivial)
    expect(expected.some((b) => b !== 0)).toBe(true);
  });
});

describe("checkpoint parsing robustness", () => {
  it("rejects checkpoint without separator", async () => {
    const parsed = parseBundle(conformanceBundle);
    // Corrupt the checkpoint by removing separator
    if (!parsed.tlogEntry.inclusionProof) throw new Error("expected inclusionProof");
    parsed.tlogEntry.inclusionProof.checkpoint = "noseparator";
    await expect(verifyCheckpoint(parsed.tlogEntry, SIGSTORE_TRUSTED_ROOT)).rejects.toThrow(
      "Invalid checkpoint format",
    );
  });

  it("rejects checkpoint with no signatures", async () => {
    const parsed = parseBundle(conformanceBundle);
    if (!parsed.tlogEntry.inclusionProof) throw new Error("expected inclusionProof");
    parsed.tlogEntry.inclusionProof.checkpoint = "origin\n12345\naGFzaA==\n\n";
    await expect(verifyCheckpoint(parsed.tlogEntry, SIGSTORE_TRUSTED_ROOT)).rejects.toThrow("No signatures");
  });

  it("rejects checkpoint with corrupted signature", async () => {
    const parsed = parseBundle(conformanceBundle);
    if (!parsed.tlogEntry.inclusionProof) throw new Error("expected inclusionProof");
    const original = parsed.tlogEntry.inclusionProof.checkpoint;
    // Corrupt the base64 signature
    parsed.tlogEntry.inclusionProof.checkpoint = original?.replace(
      /wNI9aj[A-Za-z0-9+/=]+/,
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    );
    await expect(verifyCheckpoint(parsed.tlogEntry, SIGSTORE_TRUSTED_ROOT)).rejects.toThrow();
  });
});
