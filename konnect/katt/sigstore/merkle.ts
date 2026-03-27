import type { LogCheckpoint, ParsedBundle } from "./types.ts";
import { SigstoreError } from "./types.ts";

/**
 * Verify RFC 6962 Merkle tree inclusion proof.
 * Proves the tlog entry is included in the tree whose root hash is in the checkpoint.
 *
 * Leaf hash:  SHA-256(0x00 || canonicalizedBody)
 * Node hash:  SHA-256(0x01 || left || right)
 */
export async function verifyMerkleInclusion(
  entry: ParsedBundle["tlogEntry"],
  checkpoint: LogCheckpoint,
): Promise<void> {
  const proof = entry.inclusionProof;
  if (!proof) {
    throw new SigstoreError("TLOG_INCLUSION_PROOF_ERROR", "Missing inclusion proof");
  }

  const logIndex = proof.logIndex;
  const treeSize = checkpoint.logSize;

  if (logIndex < 0n || logIndex >= treeSize) {
    throw new SigstoreError("TLOG_INCLUSION_PROOF_ERROR", `Invalid index: ${logIndex} (tree size: ${treeSize})`);
  }

  // Decompose inclusion proof into inner and border portions
  const { inner, border } = decompInclProof(logIndex, treeSize);

  if (proof.hashes.length !== inner + border) {
    throw new SigstoreError(
      "TLOG_INCLUSION_PROOF_ERROR",
      `Invalid hash count: ${proof.hashes.length}, expected ${inner + border}`,
    );
  }

  const innerHashes = proof.hashes.slice(0, inner);
  const borderHashes = proof.hashes.slice(inner);

  // Compute leaf hash
  const leafHash = await hashLeaf(entry.canonicalizedBody);

  // Chain inner hashes, then border hashes
  const innerResult = await chainInner(leafHash, innerHashes, logIndex);
  const calculatedRoot = await chainBorderRight(innerResult, borderHashes);

  // Compare with checkpoint root hash
  if (calculatedRoot.length !== checkpoint.logHash.length) {
    throw new SigstoreError("TLOG_INCLUSION_PROOF_ERROR", "Root hash length mismatch");
  }
  for (let i = 0; i < calculatedRoot.length; i++) {
    if (calculatedRoot[i] !== checkpoint.logHash[i]) {
      throw new SigstoreError("TLOG_INCLUSION_PROOF_ERROR", "Calculated root hash does not match checkpoint");
    }
  }
}

function decompInclProof(index: bigint, size: bigint): { inner: number; border: number } {
  const inner = bitLength(index ^ (size - 1n));
  const border = onesCount(index >> BigInt(inner));
  return { inner, border };
}

async function chainInner(seed: Uint8Array, hashes: Uint8Array[], index: bigint): Promise<Uint8Array> {
  let acc = seed;
  for (let i = 0; i < hashes.length; i++) {
    if ((index >> BigInt(i)) & 1n) {
      acc = await hashChildren(hashes[i], acc);
    } else {
      acc = await hashChildren(acc, hashes[i]);
    }
  }
  return acc;
}

async function chainBorderRight(seed: Uint8Array, hashes: Uint8Array[]): Promise<Uint8Array> {
  let acc = seed;
  for (const h of hashes) {
    acc = await hashChildren(h, acc);
  }
  return acc;
}

async function hashLeaf(data: Uint8Array): Promise<Uint8Array> {
  const prefixed = new Uint8Array(1 + data.length);
  prefixed[0] = 0x00;
  prefixed.set(data, 1);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", prefixed));
}

async function hashChildren(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  const combined = new Uint8Array(1 + left.length + right.length);
  combined[0] = 0x01;
  combined.set(left, 1);
  combined.set(right, 1 + left.length);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", combined));
}

function bitLength(n: bigint): number {
  if (n === 0n) return 0;
  return n.toString(2).length;
}

function onesCount(n: bigint): number {
  return n.toString(2).split("1").length - 1;
}
