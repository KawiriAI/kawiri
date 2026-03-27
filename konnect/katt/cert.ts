import type { SignatureAlgorithm } from "./der.ts";
import {
  derSignatureToRaw,
  detectSignatureAlgorithm,
  extractSerialNumber,
  extractSpki,
  parseCertificate,
  readTL,
} from "./der.ts";
import { serialsEqual } from "./util.ts";

export type { SignatureAlgorithm };

/** Parse a PEM certificate chain string into individual DER-encoded certificates */
export function parsePemChain(pem: string): Uint8Array[] {
  const certs: Uint8Array[] = [];

  const pemRegex = /-----BEGIN CERTIFICATE-----\s*([\s\S]*?)\s*-----END CERTIFICATE-----/g;
  let match: RegExpExecArray | null = pemRegex.exec(pem);

  while (match !== null) {
    const b64 = match[1].replace(/\s/g, "");
    const binary = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    certs.push(binary);
    match = pemRegex.exec(pem);
  }

  if (certs.length === 0) {
    throw new Error("No certificates found in PEM chain");
  }

  return certs;
}

/**
 * Algorithm-aware certificate signature verification.
 *
 * For ECDSA: imports SPKI, converts DER signature to raw r||s, verifies.
 * For RSA-PSS: imports SPKI, uses raw signature directly (NOT DER), verifies with saltLength 48.
 */
export async function verifyCertSignature(
  issuerSpki: Uint8Array,
  childTbs: Uint8Array,
  childSignature: Uint8Array,
  algorithm: SignatureAlgorithm,
): Promise<boolean> {
  if (algorithm === "ecdsa-p256-sha256") {
    const key = await crypto.subtle.importKey("spki", issuerSpki, { name: "ECDSA", namedCurve: "P-256" }, false, [
      "verify",
    ]);

    // ECDSA cert signatures are DER-encoded, convert to raw r||s
    const rawSig = derSignatureToRaw(childSignature, 32);

    return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, rawSig, childTbs);
  } else if (algorithm === "ecdsa-p384-sha384") {
    const key = await crypto.subtle.importKey("spki", issuerSpki, { name: "ECDSA", namedCurve: "P-384" }, false, [
      "verify",
    ]);

    const rawSig = derSignatureToRaw(childSignature, 48);

    return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-384" }, key, rawSig, childTbs);
  } else {
    // RSA-PSS SHA-384
    const key = await crypto.subtle.importKey("spki", issuerSpki, { name: "RSA-PSS", hash: "SHA-384" }, false, [
      "verify",
    ]);

    // RSA-PSS cert signatures are raw RSA bytes, NOT DER-wrapped
    return crypto.subtle.verify({ name: "RSA-PSS", saltLength: 48 }, key, childSignature, childTbs);
  }
}

/**
 * Verify a CRL's signature against the issuer's SPKI.
 * CRLs share the same outer structure as certificates: SEQUENCE { TBS, sigAlg, sigValue }.
 */
export async function verifyCrlSignature(issuerSpki: Uint8Array, crlDer: Uint8Array): Promise<boolean> {
  const parsed = parseCertificate(crlDer);
  const algo = detectSignatureAlgorithm(parsed.signatureAlgorithm);
  return verifyCertSignature(issuerSpki, parsed.tbs, parsed.signature, algo);
}

/**
 * Parse revoked serial numbers from a DER-encoded CRL.
 *
 * CRL structure:
 *   SEQUENCE {
 *     SEQUENCE (TBSCertList) {
 *       [version INTEGER]
 *       signature AlgorithmIdentifier
 *       issuer Name
 *       thisUpdate Time
 *       nextUpdate Time
 *       revokedCertificates SEQUENCE OF SEQUENCE {
 *         userCertificate INTEGER (serial)
 *         revocationDate Time
 *         [extensions]
 *       }
 *       ...
 *     }
 *     ...
 *   }
 */
export function parseRevokedSerials(crlDer: Uint8Array): Uint8Array[] {
  // Outer SEQUENCE
  const outer = readTL(crlDer, 0);
  if (outer.tag !== 0x30) throw new Error("CRL: expected outer SEQUENCE");

  // TBSCertList SEQUENCE
  const offset = outer.headerSize;
  const tbsTL = readTL(crlDer, offset);
  if (tbsTL.tag !== 0x30) throw new Error("CRL: expected TBSCertList SEQUENCE");

  const tbsEnd = offset + tbsTL.headerSize + tbsTL.length;
  let pos = offset + tbsTL.headerSize;

  // Skip optional version INTEGER (tag 0x02)
  let fieldTL = readTL(crlDer, pos);
  if (fieldTL.tag === 0x02) {
    pos += fieldTL.headerSize + fieldTL.length;
    fieldTL = readTL(crlDer, pos);
  }

  // Skip signature AlgorithmIdentifier (SEQUENCE)
  if (fieldTL.tag !== 0x30) throw new Error("CRL: expected signature algorithm SEQUENCE");
  pos += fieldTL.headerSize + fieldTL.length;

  // Skip issuer Name (SEQUENCE)
  fieldTL = readTL(crlDer, pos);
  if (fieldTL.tag !== 0x30) throw new Error("CRL: expected issuer SEQUENCE");
  pos += fieldTL.headerSize + fieldTL.length;

  // Skip thisUpdate Time
  fieldTL = readTL(crlDer, pos);
  pos += fieldTL.headerSize + fieldTL.length;

  // Skip nextUpdate Time (optional but usually present)
  if (pos < tbsEnd) {
    fieldTL = readTL(crlDer, pos);
    if (fieldTL.tag === 0x17 || fieldTL.tag === 0x18) {
      pos += fieldTL.headerSize + fieldTL.length;
    }
  }

  // Now we should be at revokedCertificates SEQUENCE (or extensions/end)
  if (pos >= tbsEnd) return []; // No revoked certs

  fieldTL = readTL(crlDer, pos);
  if (fieldTL.tag !== 0x30) {
    // Could be extensions (0xA0) or something else — no revoked certs
    return [];
  }

  // Parse SEQUENCE OF SEQUENCE { serial INTEGER, date Time, [exts] }
  const revokedSerials: Uint8Array[] = [];
  const revokedEnd = pos + fieldTL.headerSize + fieldTL.length;
  let rPos = pos + fieldTL.headerSize;

  while (rPos < revokedEnd) {
    const entryTL = readTL(crlDer, rPos);
    if (entryTL.tag !== 0x30) break;

    const entryStart = rPos + entryTL.headerSize;

    // First element: serial number INTEGER
    const serialTL = readTL(crlDer, entryStart);
    if (serialTL.tag === 0x02) {
      const serial = crlDer.subarray(
        entryStart + serialTL.headerSize,
        entryStart + serialTL.headerSize + serialTL.length,
      );
      revokedSerials.push(serial);
    }

    rPos += entryTL.headerSize + entryTL.length;
  }

  return revokedSerials;
}

/**
 * Check if a certificate has been revoked by a CRL.
 * When issuerSpki is provided, verifies the CRL signature first.
 * Returns true if the cert IS revoked.
 */
export async function checkCertRevoked(
  certDer: Uint8Array,
  crlDer: Uint8Array,
  issuerSpki?: Uint8Array,
): Promise<boolean> {
  if (issuerSpki) {
    const sigValid = await verifyCrlSignature(issuerSpki, crlDer);
    if (!sigValid) {
      throw new Error("CRL signature verification failed — CRL may be tampered");
    }
  }

  const cert = parseCertificate(certDer);
  const serial = extractSerialNumber(cert.tbs);
  const revokedSerials = parseRevokedSerials(crlDer);

  for (const revoked of revokedSerials) {
    if (serialsEqual(serial, revoked)) {
      return true;
    }
  }
  return false;
}

export { detectSignatureAlgorithm, extractSpki, parseCertificate };
