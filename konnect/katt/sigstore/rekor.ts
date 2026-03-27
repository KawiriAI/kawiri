import { derSignatureToRaw } from "../der.ts";
import { b64Decode, b64Encode, bytesEqual, toHex } from "../util.ts";
import { canonicalize } from "./json.ts";
import { verifyMerkleInclusion } from "./merkle.ts";
import type { LogCheckpoint, ParsedBundle, TransparencyLogInstance, TrustedRoot } from "./types.ts";
import { SigstoreError } from "./types.ts";

// --- SET Verification ---

/**
 * Verify the Signed Entry Timestamp (SET) for a tlog entry.
 * The SET is Rekor's signature over a JSON-canonicalized verification payload.
 */
export async function verifyTLogSET(entry: ParsedBundle["tlogEntry"], trustedRoot: TrustedRoot): Promise<void> {
  if (!entry.inclusionPromise) {
    throw new SigstoreError("TLOG_INCLUSION_PROMISE_ERROR", "No inclusion promise (SET) found");
  }

  // Construct verification payload
  const payload = {
    body: b64Encode(entry.canonicalizedBody),
    integratedTime: entry.integratedTime,
    logIndex: Number(entry.logIndex),
    logID: toHex(entry.logId),
  };

  const data = new TextEncoder().encode(canonicalize(payload));
  const signature = entry.inclusionPromise.signedEntryTimestamp;

  // Find matching tlog key (filtered by integratedTime)
  const entryTime = new Date(entry.integratedTime * 1000);
  const tlog = findTLogByLogId(entry.logId, trustedRoot.tlogs, entryTime);
  if (!tlog) {
    throw new SigstoreError(
      "TLOG_INCLUSION_PROMISE_ERROR",
      "No matching transparency log key found for SET verification",
    );
  }

  const verified = await verifyWithTLogKey(data, signature, tlog);
  if (!verified) {
    throw new SigstoreError("TLOG_INCLUSION_PROMISE_ERROR", "SET signature verification failed");
  }
}

// --- Checkpoint Verification ---

const CHECKPOINT_SEPARATOR = "\n\n";
const SIGNATURE_REGEX = /\u2014 (\S+) (\S+)\n/g;

/**
 * Parse and verify a signed checkpoint from an inclusion proof.
 * Returns the parsed checkpoint (origin, logSize, logHash).
 */
export async function verifyCheckpoint(
  entry: ParsedBundle["tlogEntry"],
  trustedRoot: TrustedRoot,
): Promise<LogCheckpoint> {
  if (!entry.inclusionProof) {
    throw new SigstoreError("TLOG_INCLUSION_PROOF_ERROR", "No inclusion proof found");
  }

  const envelope = entry.inclusionProof.checkpoint;
  if (!envelope?.includes(CHECKPOINT_SEPARATOR)) {
    throw new SigstoreError("TLOG_INCLUSION_PROOF_ERROR", "Invalid checkpoint format");
  }

  // Split into note (header) and signatures
  const splitIdx = envelope.indexOf(CHECKPOINT_SEPARATOR);
  const note = envelope.slice(0, splitIdx + 1); // Include trailing newline
  const sigData = envelope.slice(splitIdx + CHECKPOINT_SEPARATOR.length);

  // Parse checkpoint header
  const lines = note.trimEnd().split("\n");
  if (lines.length < 3) {
    throw new SigstoreError("TLOG_INCLUSION_PROOF_ERROR", "Too few lines in checkpoint header");
  }

  const origin = lines[0];
  const logSize = BigInt(lines[1]);
  const logHash = b64Decode(lines[2]);

  // Parse signatures
  const matches = [...sigData.matchAll(SIGNATURE_REGEX)];
  if (matches.length === 0) {
    throw new SigstoreError("TLOG_INCLUSION_PROOF_ERROR", "No signatures in checkpoint");
  }

  // Verify at least one signature
  const noteBytes = new TextEncoder().encode(note);
  const entryTime = new Date(entry.integratedTime * 1000);
  let anyVerified = false;

  for (const match of matches) {
    const [, name, sigB64] = match;
    const sigBytes = b64Decode(sigB64);
    if (sigBytes.length < 5) continue;

    const keyHint = sigBytes.subarray(0, 4);
    const sig = sigBytes.subarray(4);

    // Find matching tlog by key hint (first 4 bytes of logID), filtered by validFor
    const tlog = findTLogByKeyHint(keyHint, name, trustedRoot.tlogs, entryTime);
    if (!tlog) continue;

    const valid = await verifyWithTLogKey(noteBytes, sig, tlog);
    if (valid) {
      anyVerified = true;
      break;
    }
  }

  if (!anyVerified) {
    throw new SigstoreError("TLOG_INCLUSION_PROOF_ERROR", "Checkpoint signature verification failed");
  }

  return { origin, logSize, logHash };
}

// --- Tlog Body Verification ---

/**
 * Verify the tlog entry body matches the DSSE envelope content.
 */
export async function verifyTLogBody(
  entry: ParsedBundle["tlogEntry"],
  envelope: ParsedBundle["envelope"],
): Promise<void> {
  // Parse canonicalizedBody as JSON
  const bodyStr = new TextDecoder().decode(entry.canonicalizedBody);
  let body: Record<string, unknown>;
  try {
    body = JSON.parse(bodyStr);
  } catch {
    throw new SigstoreError("TLOG_BODY_ERROR", "Failed to parse canonicalized body as JSON");
  }

  const kind = body.kind as string;
  const apiVersion = body.apiVersion as string;

  // Verify kind/version matches entry metadata
  if (kind !== entry.kindVersion.kind) {
    throw new SigstoreError("TLOG_BODY_ERROR", `Kind mismatch: body=${kind}, entry=${entry.kindVersion.kind}`);
  }

  if (apiVersion !== entry.kindVersion.version) {
    throw new SigstoreError(
      "TLOG_BODY_ERROR",
      `Version mismatch: body=${apiVersion}, entry=${entry.kindVersion.version}`,
    );
  }

  const spec = body.spec as Record<string, unknown>;
  if (!spec) {
    throw new SigstoreError("TLOG_BODY_ERROR", "Missing spec in canonicalized body");
  }

  if (kind === "dsse") {
    if (apiVersion === "0.0.1") {
      await verifyDSSEBody001(spec, envelope);
    } else if (apiVersion === "0.0.2") {
      await verifyDSSEBody002(spec, envelope);
    } else {
      throw new SigstoreError("TLOG_BODY_ERROR", `Unsupported dsse version: ${apiVersion}`);
    }
  } else if (kind === "hashedrekord") {
    // hashedrekord: verify signature and digest match
    await verifyHashedRekordBody(spec, envelope);
  } else {
    throw new SigstoreError("TLOG_BODY_ERROR", `Unsupported tlog entry kind: ${kind}`);
  }
}

/** Verify DSSE v0.0.1 body against envelope. */
async function verifyDSSEBody001(spec: Record<string, unknown>, envelope: ParsedBundle["envelope"]): Promise<void> {
  // Check signature matches
  const sigs = spec.signatures as Array<Record<string, string>> | undefined;
  if (!sigs || sigs.length === 0) {
    throw new SigstoreError("TLOG_BODY_ERROR", "No signatures in dsse body");
  }
  const tlogSig = b64Decode(sigs[0].signature);
  if (!bytesEqual(tlogSig, envelope.signature)) {
    throw new SigstoreError("TLOG_BODY_ERROR", "DSSE signature mismatch in tlog body");
  }

  // Check payload hash
  const payloadHash = spec.payloadHash as Record<string, string> | undefined;
  if (payloadHash) {
    const hashValue = payloadHash.value;
    const computed = toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", envelope.payload)));
    if (hashValue !== computed) {
      throw new SigstoreError("TLOG_BODY_ERROR", "DSSE payload hash mismatch");
    }
  }
}

/** Verify DSSE v0.0.2 body against envelope. */
async function verifyDSSEBody002(spec: Record<string, unknown>, envelope: ParsedBundle["envelope"]): Promise<void> {
  const sigs = spec.signatures as Array<Record<string, unknown>> | undefined;
  if (!sigs || sigs.length === 0) {
    throw new SigstoreError("TLOG_BODY_ERROR", "No signatures in dsse body");
  }

  // v0.0.2 uses content (binary) instead of signature (base64)
  const content = sigs[0].content;
  if (!content || typeof content !== "string") {
    throw new SigstoreError("TLOG_BODY_ERROR", "Missing signature content in dsse v0.0.2 body");
  }
  const tlogSig = b64Decode(content);
  if (!bytesEqual(tlogSig, envelope.signature)) {
    throw new SigstoreError("TLOG_BODY_ERROR", "DSSE signature mismatch in tlog body");
  }

  const payloadHash = spec.payloadHash as Record<string, string> | undefined;
  if (!payloadHash?.digest) {
    throw new SigstoreError("TLOG_BODY_ERROR", "Missing payloadHash.digest in dsse v0.0.2 body");
  }
  const digestBytes = b64Decode(payloadHash.digest);
  const computed = new Uint8Array(await crypto.subtle.digest("SHA-256", envelope.payload));
  if (!bytesEqual(digestBytes, computed)) {
    throw new SigstoreError("TLOG_BODY_ERROR", "DSSE payload hash mismatch");
  }
}

/** Verify hashedrekord body against envelope. */
async function verifyHashedRekordBody(
  spec: Record<string, unknown>,
  envelope: ParsedBundle["envelope"],
): Promise<void> {
  const sigObj = spec.signature as Record<string, unknown> | undefined;
  if (!sigObj?.content || typeof sigObj.content !== "string") {
    throw new SigstoreError("TLOG_BODY_ERROR", "Missing signature.content in hashedrekord body");
  }
  const tlogSig = b64Decode(sigObj.content);
  if (!bytesEqual(tlogSig, envelope.signature)) {
    throw new SigstoreError("TLOG_BODY_ERROR", "Signature mismatch in hashedrekord body");
  }
}

/**
 * Full tlog entry verification: body + inclusion (SET and/or Merkle proof).
 */
export async function verifyTLogEntry(
  entry: ParsedBundle["tlogEntry"],
  envelope: ParsedBundle["envelope"],
  trustedRoot: TrustedRoot,
): Promise<void> {
  // Step 1: Verify body matches envelope
  await verifyTLogBody(entry, envelope);

  // Step 2: Verify inclusion — at least one mechanism must succeed
  let inclusionVerified = false;
  const inclusionErrors: string[] = [];

  // Try SET (inclusion promise)
  if (entry.inclusionPromise) {
    try {
      await verifyTLogSET(entry, trustedRoot);
      inclusionVerified = true;
    } catch (e) {
      inclusionErrors.push(`SET: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  // Try inclusion proof (checkpoint + Merkle)
  if (!inclusionVerified && entry.inclusionProof) {
    try {
      // Consistency check: entry.logIndex must match inclusionProof.logIndex
      if (entry.logIndex !== entry.inclusionProof.logIndex) {
        throw new SigstoreError(
          "TLOG_INCLUSION_PROOF_ERROR",
          `logIndex mismatch: entry=${entry.logIndex}, proof=${entry.inclusionProof.logIndex}`,
        );
      }

      const checkpoint = await verifyCheckpoint(entry, trustedRoot);

      // Consistency check: proof treeSize and rootHash must match signed checkpoint
      if (entry.inclusionProof.treeSize !== checkpoint.logSize) {
        throw new SigstoreError(
          "TLOG_INCLUSION_PROOF_ERROR",
          `treeSize mismatch: proof=${entry.inclusionProof.treeSize}, checkpoint=${checkpoint.logSize}`,
        );
      }
      if (!bytesEqual(entry.inclusionProof.rootHash, checkpoint.logHash)) {
        throw new SigstoreError(
          "TLOG_INCLUSION_PROOF_ERROR",
          "rootHash mismatch between inclusion proof and signed checkpoint",
        );
      }

      await verifyMerkleInclusion(entry, checkpoint);
      inclusionVerified = true;
    } catch (e) {
      inclusionErrors.push(`Merkle: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  if (!inclusionVerified) {
    const details = inclusionErrors.length > 0 ? `: ${inclusionErrors.join("; ")}` : "";
    throw new SigstoreError("TLOG_ERROR", `No inclusion mechanism could be verified (SET or Merkle proof)${details}`);
  }
}

// --- Helpers ---

function findTLogByLogId(
  logId: Uint8Array,
  tlogs: TransparencyLogInstance[],
  timestamp?: Date,
): TransparencyLogInstance | undefined {
  for (const tlog of tlogs) {
    const keyIdBytes = b64Decode(tlog.logId.keyId);
    if (!bytesEqual(keyIdBytes, logId)) continue;
    if (timestamp && !isWithinValidFor(timestamp, tlog.publicKey.validFor)) continue;
    return tlog;
  }
  return undefined;
}

function findTLogByKeyHint(
  keyHint: Uint8Array,
  name: string,
  tlogs: TransparencyLogInstance[],
  timestamp?: Date,
): TransparencyLogInstance | undefined {
  for (const tlog of tlogs) {
    const keyIdBytes = b64Decode(tlog.logId.keyId);
    if (keyIdBytes.length < 4) continue;
    let hintMatch = true;
    for (let i = 0; i < 4; i++) {
      if (keyIdBytes[i] !== keyHint[i]) {
        hintMatch = false;
        break;
      }
    }
    if (!hintMatch) continue;
    if (timestamp && !isWithinValidFor(timestamp, tlog.publicKey.validFor)) continue;
    // Also match tlog name/baseURL
    if (tlog.baseUrl.includes(name.split(" ")[0])) return tlog;
  }
  // Fallback: just match by key hint without name
  for (const tlog of tlogs) {
    const keyIdBytes = b64Decode(tlog.logId.keyId);
    if (keyIdBytes.length < 4) continue;
    let hintMatch = true;
    for (let i = 0; i < 4; i++) {
      if (keyIdBytes[i] !== keyHint[i]) {
        hintMatch = false;
        break;
      }
    }
    if (!hintMatch) continue;
    if (timestamp && !isWithinValidFor(timestamp, tlog.publicKey.validFor)) continue;
    return tlog;
  }
  return undefined;
}

/** Check if a time falls within a validFor window */
function isWithinValidFor(time: Date, validFor: { start: string; end?: string }): boolean {
  if (time < new Date(validFor.start)) return false;
  if (validFor.end && time > new Date(validFor.end)) return false;
  return true;
}

async function verifyWithTLogKey(
  data: Uint8Array,
  signature: Uint8Array,
  tlog: TransparencyLogInstance,
): Promise<boolean> {
  const keyDer = b64Decode(tlog.publicKey.rawBytes);
  const keyDetails = tlog.publicKey.keyDetails;

  try {
    if (keyDetails === "PKIX_ED25519") {
      const key = await crypto.subtle.importKey("spki", keyDer, { name: "Ed25519" }, false, ["verify"]);
      return crypto.subtle.verify({ name: "Ed25519" }, key, signature, data);
    } else {
      // ECDSA P-256 SHA-256
      const key = await crypto.subtle.importKey("spki", keyDer, { name: "ECDSA", namedCurve: "P-256" }, false, [
        "verify",
      ]);
      // SET/checkpoint signatures are DER-encoded ECDSA
      let rawSig: Uint8Array;
      try {
        rawSig = derSignatureToRaw(signature, 32);
      } catch {
        rawSig = signature; // Already raw
      }
      return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, rawSig, data);
    }
  } catch {
    return false;
  }
}
