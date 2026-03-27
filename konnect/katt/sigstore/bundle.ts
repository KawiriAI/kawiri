import { b64Decode } from "../util.ts";
import type { ParsedBundle } from "./types.ts";
import { SigstoreError } from "./types.ts";

const BUNDLE_V02 = "application/vnd.dev.sigstore.bundle+json;version=0.2";
const BUNDLE_V03 = "application/vnd.dev.sigstore.bundle.v0.3+json";

/** Parse and validate a Sigstore bundle from JSON input. */
export function parseBundle(input: unknown): ParsedBundle {
  if (!input || typeof input !== "object") {
    throw new SigstoreError("BUNDLE_PARSE_ERROR", "Bundle must be a JSON object");
  }

  const bundle = input as Record<string, unknown>;
  const mediaType = bundle.mediaType as string;

  if (mediaType !== BUNDLE_V02 && mediaType !== BUNDLE_V03) {
    throw new SigstoreError("BUNDLE_PARSE_ERROR", `Unsupported bundle mediaType: ${mediaType}. Expected v0.2 or v0.3`);
  }

  // Parse verification material
  const vm = bundle.verificationMaterial as Record<string, unknown> | undefined;
  if (!vm) {
    throw new SigstoreError("BUNDLE_PARSE_ERROR", "Missing verificationMaterial");
  }

  // Extract signing certificate
  const signingCert = extractSigningCert(vm, mediaType);

  // Parse DSSE envelope
  const envelope = parseEnvelope(bundle);

  // Parse tlog entries
  const tlogEntries = vm.tlogEntries as Array<Record<string, unknown>> | undefined;
  if (!tlogEntries || tlogEntries.length === 0) {
    throw new SigstoreError("BUNDLE_PARSE_ERROR", "No tlog entries found");
  }

  const parsedTlogEntries = tlogEntries.map((e) => parseTlogEntry(e));

  // Parse RFC 3161 timestamps (v0.3 only)
  const rfc3161Timestamps: Uint8Array[] = [];
  const tsData = vm.timestampVerificationData as Record<string, unknown> | undefined;
  if (tsData?.rfc3161Timestamps) {
    const timestamps = tsData.rfc3161Timestamps as Array<Record<string, string>>;
    for (const ts of timestamps) {
      if (ts.signedTimestamp) {
        rfc3161Timestamps.push(b64Decode(ts.signedTimestamp));
      }
    }
  }

  return {
    mediaType,
    signingCert,
    envelope,
    tlogEntry: parsedTlogEntries[0],
    tlogEntries: parsedTlogEntries,
    rfc3161Timestamps,
  };
}

function extractSigningCert(vm: Record<string, unknown>, mediaType: string): Uint8Array {
  // v0.3: single certificate
  const cert = vm.certificate as Record<string, string> | undefined;
  if (cert?.rawBytes) {
    return b64Decode(cert.rawBytes);
  }

  // v0.2: x509CertificateChain (use first = leaf cert)
  const chain = vm.x509CertificateChain as Record<string, unknown> | undefined;
  if (chain?.certificates) {
    const certs = chain.certificates as Array<Record<string, string>>;
    if (certs.length > 0 && certs[0].rawBytes) {
      return b64Decode(certs[0].rawBytes);
    }
  }

  throw new SigstoreError("BUNDLE_PARSE_ERROR", `Could not extract signing certificate from ${mediaType} bundle`);
}

function parseEnvelope(bundle: Record<string, unknown>): ParsedBundle["envelope"] {
  const dsse = bundle.dsseEnvelope as Record<string, unknown> | undefined;
  if (!dsse) {
    throw new SigstoreError("BUNDLE_PARSE_ERROR", "Missing dsseEnvelope");
  }

  const payloadType = dsse.payloadType as string;
  const payloadB64 = dsse.payload as string;
  const signatures = dsse.signatures as Array<Record<string, string>>;

  if (!payloadType || !payloadB64 || !signatures || signatures.length === 0) {
    throw new SigstoreError("BUNDLE_PARSE_ERROR", "Invalid dsseEnvelope structure");
  }

  return {
    payload: b64Decode(payloadB64),
    payloadType,
    signature: b64Decode(signatures[0].sig),
  };
}

function parseTlogEntry(entry: Record<string, unknown>): ParsedBundle["tlogEntry"] {
  const logIndex = BigInt(entry.logIndex as string | number);
  const logId = b64Decode((entry.logId as Record<string, string>).keyId);
  const integratedTime = Number(entry.integratedTime as string | number);
  if (!Number.isFinite(integratedTime) || integratedTime <= 0) {
    throw new SigstoreError("BUNDLE_PARSE_ERROR", `Invalid integratedTime: ${entry.integratedTime}`);
  }
  const canonicalizedBody = b64Decode(entry.canonicalizedBody as string);
  const kindVersion = entry.kindVersion as { kind: string; version: string };

  let inclusionPromise: ParsedBundle["tlogEntry"]["inclusionPromise"];
  const promise = entry.inclusionPromise as Record<string, string> | undefined;
  if (promise?.signedEntryTimestamp) {
    inclusionPromise = {
      signedEntryTimestamp: b64Decode(promise.signedEntryTimestamp),
    };
  }

  let inclusionProof: ParsedBundle["tlogEntry"]["inclusionProof"];
  const proof = entry.inclusionProof as Record<string, unknown> | undefined;
  if (proof) {
    const checkpoint = proof.checkpoint as Record<string, string> | string;
    const checkpointStr =
      typeof checkpoint === "string" ? checkpoint : ((checkpoint as Record<string, string>)?.envelope ?? "");

    if (checkpointStr) {
      inclusionProof = {
        logIndex: BigInt(proof.logIndex as string | number),
        rootHash: b64Decode(proof.rootHash as string),
        treeSize: BigInt(proof.treeSize as string | number),
        hashes: (proof.hashes as string[]).map((h) => b64Decode(h)),
        checkpoint: checkpointStr,
      };
    }
  }

  return {
    logIndex,
    logId,
    integratedTime,
    canonicalizedBody,
    kindVersion,
    inclusionPromise,
    inclusionProof,
  };
}
