import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { parseBundle } from "@katt/sigstore/bundle.js";
import { verifyMerkleInclusion } from "@katt/sigstore/merkle.js";
import { verifyCheckpoint, verifyTLogBody, verifyTLogEntry, verifyTLogSET } from "@katt/sigstore/rekor.js";
import SIGSTORE_TRUSTED_ROOT from "@katt/sigstore/trusted-root.js";

if (!import.meta.dirname) throw new Error("expected import.meta.dirname");
const bundleJson = JSON.parse(readFileSync(resolve(import.meta.dirname, "fixtures/sigstore-bundle.json"), "utf-8"));

describe("verifyTLogSET", () => {
  it("verifies SET from real bundle", async () => {
    const parsed = parseBundle(bundleJson);
    await expect(verifyTLogSET(parsed.tlogEntry, SIGSTORE_TRUSTED_ROOT)).resolves.toBeUndefined();
  });

  it("rejects corrupted SET signature", async () => {
    const parsed = parseBundle(bundleJson);
    // Corrupt the SET
    const corrupted = {
      ...parsed.tlogEntry,
      inclusionPromise: {
        signedEntryTimestamp: new Uint8Array(parsed.tlogEntry.inclusionPromise?.signedEntryTimestamp ?? []),
      },
    };
    corrupted.inclusionPromise.signedEntryTimestamp[5] ^= 0xff;

    await expect(verifyTLogSET(corrupted, SIGSTORE_TRUSTED_ROOT)).rejects.toThrow(/SET|inclusion promise/i);
  });
});

describe("verifyCheckpoint", () => {
  it("parses checkpoint from real bundle", async () => {
    const parsed = parseBundle(bundleJson);
    const checkpoint = await verifyCheckpoint(parsed.tlogEntry, SIGSTORE_TRUSTED_ROOT);

    expect(checkpoint.origin).toContain("rekor.sigstore.dev");
    expect(Number(checkpoint.logSize)).toBeGreaterThan(0);
    expect(checkpoint.logHash.length).toBe(32);
  });

  it("verifies checkpoint signature", async () => {
    const parsed = parseBundle(bundleJson);
    // Should not throw
    const checkpoint = await verifyCheckpoint(parsed.tlogEntry, SIGSTORE_TRUSTED_ROOT);
    expect(checkpoint).toBeDefined();
  });
});

describe("verifyMerkleInclusion", () => {
  it("verifies Merkle inclusion proof from real bundle", async () => {
    const parsed = parseBundle(bundleJson);
    const checkpoint = await verifyCheckpoint(parsed.tlogEntry, SIGSTORE_TRUSTED_ROOT);

    // Should not throw
    await expect(verifyMerkleInclusion(parsed.tlogEntry, checkpoint)).resolves.toBeUndefined();
  });

  it("rejects corrupted inclusion proof hash", async () => {
    const parsed = parseBundle(bundleJson);
    const checkpoint = await verifyCheckpoint(parsed.tlogEntry, SIGSTORE_TRUSTED_ROOT);

    // Corrupt one of the proof hashes
    const proof = parsed.tlogEntry.inclusionProof;
    if (!proof) throw new Error("expected inclusionProof");
    const corrupted = {
      ...parsed.tlogEntry,
      inclusionProof: {
        ...proof,
        hashes: [...proof.hashes],
      },
    };
    const firstHash = new Uint8Array(corrupted.inclusionProof.hashes[0]);
    firstHash[0] ^= 0xff;
    corrupted.inclusionProof.hashes[0] = firstHash;

    await expect(verifyMerkleInclusion(corrupted, checkpoint)).rejects.toThrow(/root hash|inclusion proof/i);
  });
});

describe("verifyTLogBody", () => {
  it("verifies tlog body matches envelope content", async () => {
    const parsed = parseBundle(bundleJson);
    await expect(verifyTLogBody(parsed.tlogEntry, parsed.envelope)).resolves.toBeUndefined();
  });
});

describe("verifyTLogEntry", () => {
  it("full tlog entry verification succeeds on real bundle", async () => {
    const parsed = parseBundle(bundleJson);
    await expect(verifyTLogEntry(parsed.tlogEntry, parsed.envelope, SIGSTORE_TRUSTED_ROOT)).resolves.toBeUndefined();
  });
});
