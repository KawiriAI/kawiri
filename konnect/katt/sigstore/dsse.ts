import { derSignatureToRaw } from "../der.ts";
import type { ParsedBundle } from "./types.ts";
import { SigstoreError } from "./types.ts";

/**
 * DSSE Pre-Authentication Encoding (PAE).
 * Format: "DSSEv1" + SP + len(payloadType) + SP + payloadType + SP + len(payload) + SP + payload
 * Lengths are BYTE lengths as ASCII decimal.
 */
export function preAuthEncoding(payloadType: string, payload: Uint8Array): Uint8Array {
  const enc = new TextEncoder();
  const typeBytes = enc.encode(payloadType);
  // "DSSEv1 {typeLen} {type} {payloadLen} " — note trailing space before payload
  const prefix = `DSSEv1 ${typeBytes.length} ${payloadType} ${payload.length} `;
  const prefixBytes = enc.encode(prefix);
  const result = new Uint8Array(prefixBytes.length + payload.length);
  result.set(prefixBytes, 0);
  result.set(payload, prefixBytes.length);
  return result;
}

/**
 * Verify the DSSE envelope signature against the signing key.
 * 1. Compute PAE(payloadType, payload)
 * 2. Convert DER ECDSA signature to raw r||s
 * 3. Verify with the key's algorithm (P-256/SHA-256 or P-384/SHA-384)
 */
export async function verifyDSSESignature(envelope: ParsedBundle["envelope"], signingKey: CryptoKey): Promise<boolean> {
  const paeBytes = preAuthEncoding(envelope.payloadType, envelope.payload);

  // Derive component size and hash from the key's algorithm
  const keyAlgo = signingKey.algorithm as EcKeyAlgorithm;
  const isP384 = keyAlgo.namedCurve === "P-384";
  const componentSize = isP384 ? 48 : 32;
  const hash = isP384 ? "SHA-384" : "SHA-256";

  // DSSE signature is DER-encoded ECDSA — convert to raw r||s for WebCrypto
  let rawSig: Uint8Array;
  try {
    rawSig = derSignatureToRaw(envelope.signature, componentSize);
  } catch {
    throw new SigstoreError("SIGNATURE_ERROR", "Failed to decode DER ECDSA signature");
  }

  const valid = await crypto.subtle.verify({ name: "ECDSA", hash }, signingKey, rawSig, paeBytes);

  if (!valid) {
    throw new SigstoreError("SIGNATURE_ERROR", "DSSE signature verification failed");
  }

  return true;
}
