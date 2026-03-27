import { verifyCertSignature } from "../cert.ts";
import {
  decodeStringExtension,
  derSignatureToRaw,
  detectSignatureAlgorithm,
  extractExtensions,
  extractSpki,
  extractValidity,
  findExtensionByOid,
  hasKeyCertSignUsage,
  isCaCert,
  parseCertificate,
  parseSctList,
  readTL,
  removeTbsExtension,
} from "../der.ts";
import { encodeOid } from "../tdx/fmspc.ts";
import { b64Decode, bytesEqual } from "../util.ts";
import type { FulcioIdentity, TransparencyLogInstance, TrustedRoot } from "./types.ts";
import { EXTENSION_OID_SCT, FULCIO_OIDS, SigstoreError } from "./types.ts";

/**
 * Verify the Fulcio signing certificate chains to a trusted CA.
 * Returns the extracted identity and SCT extension value (if present).
 *
 * Fulcio certs are short-lived (~10 min). We do NOT reject for expiry —
 * the collected timestamps prove the cert was valid when used.
 */
export async function verifyFulcioCert(
  signingCertDer: Uint8Array,
  trustedRoot: TrustedRoot,
): Promise<{ identity: FulcioIdentity; signingKey: CryptoKey }> {
  const signingCert = parseCertificate(signingCertDer);

  // Use signing cert's notBefore as proxy for issuance time
  const certValidity = extractValidity(signingCert.tbs);
  const certIssuedAt = certValidity.notBefore;

  // Find matching Fulcio CA — try each CA's cert chain
  let verified = false;
  for (const ca of trustedRoot.certificateAuthorities) {
    const certs = ca.certChain.certificates;
    if (certs.length === 0) continue;

    // Skip CAs not valid at cert issuance time
    if (!isWithinValidFor(certIssuedAt, ca.validFor)) continue;

    try {
      if (certs.length === 1) {
        // Self-signed root: verify signing cert directly against root
        const rootDer = b64Decode(certs[0].rawBytes);
        const rootCert = parseCertificate(rootDer);
        if (!isCaCert(rootCert.tbs) || !hasKeyCertSignUsage(rootCert.tbs)) continue;
        const rootSpki = extractSpki(rootCert.tbs);
        const algo = detectSignatureAlgorithm(signingCert.signatureAlgorithm);
        const valid = await verifyCertSignature(rootSpki, signingCert.tbs, signingCert.signature, algo);
        if (valid) {
          verified = true;
          break;
        }
      } else {
        // Chain: intermediate (first) + root (last)
        // Verify: root → intermediate → signing cert
        const intermediateDer = b64Decode(certs[0].rawBytes);
        const rootDer = b64Decode(certs[certs.length - 1].rawBytes);

        // Verify root is a CA with keyCertSign
        const rootCert = parseCertificate(rootDer);
        if (!isCaCert(rootCert.tbs) || !hasKeyCertSignUsage(rootCert.tbs)) continue;
        const rootSpki = extractSpki(rootCert.tbs);
        const intermediateCert = parseCertificate(intermediateDer);

        // Verify intermediate is a CA with keyCertSign
        if (!isCaCert(intermediateCert.tbs) || !hasKeyCertSignUsage(intermediateCert.tbs)) continue;

        const intAlgo = detectSignatureAlgorithm(intermediateCert.signatureAlgorithm);
        const intValid = await verifyCertSignature(rootSpki, intermediateCert.tbs, intermediateCert.signature, intAlgo);
        if (!intValid) continue;

        // Verify signing cert is signed by intermediate
        const intermediateSpki = extractSpki(intermediateCert.tbs);
        const sigAlgo = detectSignatureAlgorithm(signingCert.signatureAlgorithm);
        const sigValid = await verifyCertSignature(intermediateSpki, signingCert.tbs, signingCert.signature, sigAlgo);

        if (sigValid) {
          verified = true;
          break;
        }
      }
    } catch {}
  }

  if (!verified) {
    throw new SigstoreError("CERTIFICATE_ERROR", "Signing certificate does not chain to any trusted Fulcio CA");
  }

  // Verify leaf cert has digitalSignature keyUsage (bit 0)
  if (!hasDigitalSignatureUsage(signingCert.tbs)) {
    throw new SigstoreError("CERTIFICATE_ERROR", "Signing certificate lacks digitalSignature key usage");
  }

  // Verify leaf cert has CodeSigning EKU (OID 1.3.6.1.5.5.7.3.3)
  if (!hasCodeSigningEKU(signingCert.tbs)) {
    throw new SigstoreError("CERTIFICATE_ERROR", "Signing certificate lacks CodeSigning extended key usage");
  }

  // Extract identity from extensions
  const identity = extractFulcioIdentity(signingCert.tbs);

  // Import the signing key for DSSE verification
  const signingSpki = extractSpki(signingCert.tbs);
  const signingKey = await importEcKeyFromSpki(signingSpki);

  return { identity, signingKey };
}

/** Extract Fulcio identity from X.509 extensions. */
export function extractFulcioIdentity(tbs: Uint8Array): FulcioIdentity {
  const extensions = extractExtensions(tbs);

  // Try v2 issuer first, fall back to v1
  const issuerV2Oid = encodeOid(FULCIO_OIDS.issuerV2);
  const issuerV1Oid = encodeOid(FULCIO_OIDS.issuer);
  const issuerExt = findExtensionByOid(extensions, issuerV2Oid) ?? findExtensionByOid(extensions, issuerV1Oid);
  if (!issuerExt) {
    throw new SigstoreError("CERTIFICATE_ERROR", "Missing OIDC issuer extension in Fulcio cert");
  }
  const oidcIssuer = decodeStringExtension(issuerExt);

  const repoExt = findExtensionByOid(extensions, encodeOid(FULCIO_OIDS.sourceRepoUri));
  const sourceRepoUri = repoExt ? decodeStringExtension(repoExt) : "";

  const refExt = findExtensionByOid(extensions, encodeOid(FULCIO_OIDS.sourceRepoRef));
  const sourceRepoRef = refExt ? decodeStringExtension(refExt) : "";

  const digestExt = findExtensionByOid(extensions, encodeOid(FULCIO_OIDS.sourceRepoDigest));
  const sourceRepoDigest = digestExt ? decodeStringExtension(digestExt) : "";

  const signerExt = findExtensionByOid(extensions, encodeOid(FULCIO_OIDS.buildSignerUri));
  const buildSignerUri = signerExt ? decodeStringExtension(signerExt) : "";

  return { oidcIssuer, sourceRepoUri, sourceRepoRef, sourceRepoDigest, buildSignerUri };
}

/**
 * Verify SCTs embedded in the Fulcio signing certificate.
 * Returns the number of verified SCTs.
 * Tries all possible issuer certs from the trusted root since different CAs
 * may have different intermediates.
 */
export async function verifySCTs(signingCertDer: Uint8Array, trustedRoot: TrustedRoot): Promise<number> {
  const cert = parseCertificate(signingCertDer);
  const extensions = extractExtensions(cert.tbs);

  // Find the SCT extension
  const sctOidBytes = encodeOid(EXTENSION_OID_SCT);
  const sctExt = findExtensionByOid(extensions, sctOidBytes);
  if (!sctExt) return 0;

  // Parse SCT list
  const scts = parseSctList(sctExt.value);
  if (scts.length === 0) return 0;

  // Remove SCT extension from TBS and re-encode for PreCert
  const modifiedTbs = removeTbsExtension(cert.tbs, sctOidBytes);

  // Collect all possible issuer certs from all CAs
  const possibleIssuers: Uint8Array[] = [];
  for (const ca of trustedRoot.certificateAuthorities) {
    for (const certEntry of ca.certChain.certificates) {
      possibleIssuers.push(b64Decode(certEntry.rawBytes));
    }
  }

  let verifiedCount = 0;

  for (const sct of scts) {
    // Find matching CT log by logID (filtered by SCT timestamp)
    const sctTime = new Date(Number(sct.timestamp));
    const ctlog = findCtLogByLogId(sct.logID, trustedRoot.ctlogs, sctTime);
    if (!ctlog) continue;

    // Try each possible issuer cert
    let sctVerified = false;
    for (const issuerDer of possibleIssuers) {
      try {
        const verified = await verifySingleSCT(sct, modifiedTbs, issuerDer, ctlog);
        if (verified) {
          sctVerified = true;
          break;
        }
      } catch {
        // Try next issuer
      }
    }
    if (sctVerified) verifiedCount++;
  }

  return verifiedCount;
}

/** Verify a single SCT against a specific issuer cert and CT log key. */
async function verifySingleSCT(
  sct: ReturnType<typeof parseSctList>[0],
  modifiedTbs: Uint8Array,
  issuerDer: Uint8Array,
  ctlog: TransparencyLogInstance,
): Promise<boolean> {
  // Compute SHA-256 of issuer's SPKI
  const issuerCert = parseCertificate(issuerDer);
  const issuerSpki = extractSpki(issuerCert.tbs);
  const issuerKeyHash = new Uint8Array(await crypto.subtle.digest("SHA-256", issuerSpki));

  // Build the digitally-signed struct per RFC 6962 section 3.2
  const tbsLen = modifiedTbs.length;
  const extLen = sct.extensions.length;
  const data = new Uint8Array(1 + 1 + 8 + 2 + 32 + 3 + tbsLen + 2 + extLen);
  let off = 0;

  data[off++] = sct.version;
  data[off++] = 0x00; // signature_type = certificate_timestamp
  const ts = sct.timestamp;
  for (let i = 7; i >= 0; i--) {
    data[off++] = Number((ts >> BigInt(i * 8)) & 0xffn);
  }
  data[off++] = 0x00;
  data[off++] = 0x01; // entry_type = precert_entry
  data.set(issuerKeyHash, off);
  off += 32;
  data[off++] = (tbsLen >> 16) & 0xff;
  data[off++] = (tbsLen >> 8) & 0xff;
  data[off++] = tbsLen & 0xff;
  data.set(modifiedTbs, off);
  off += tbsLen;
  data[off++] = (extLen >> 8) & 0xff;
  data[off++] = extLen & 0xff;
  if (extLen > 0) data.set(sct.extensions, off);

  // Import CT log key and verify
  const keyDer = b64Decode(ctlog.publicKey.rawBytes);
  const key = await crypto.subtle.importKey("spki", keyDer, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  const rawSig = derSignatureToRaw(sct.signature, 32);
  return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, rawSig, data);
}

/**
 * Import an EC public key from SPKI, detecting the curve from the AlgorithmIdentifier.
 *
 * SPKI structure: SEQUENCE { AlgorithmIdentifier, BIT STRING publicKey }
 * For EC keys, AlgorithmIdentifier contains: SEQUENCE { OID ecPublicKey, OID namedCurve }
 */
// OID 1.2.840.10045.3.1.7 = P-256
const _OID_P256 = new Uint8Array([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);
// OID 1.3.132.0.34 = P-384
const OID_P384 = new Uint8Array([0x2b, 0x81, 0x04, 0x00, 0x22]);

async function importEcKeyFromSpki(spki: Uint8Array): Promise<CryptoKey> {
  // Check which curve OID is present in the SPKI
  const isP384 = containsBytes(spki, OID_P384);
  const curve = isP384 ? "P-384" : "P-256";
  return crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: curve }, false, ["verify"]);
}

function containsBytes(haystack: Uint8Array, needle: Uint8Array): boolean {
  outer: for (let i = 0; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return true;
  }
  return false;
}

/** Find a CT log instance by comparing SHA-256(publicKey) with the SCT's logID. */
function findCtLogByLogId(
  logID: Uint8Array,
  ctlogs: TransparencyLogInstance[],
  timestamp?: Date,
): TransparencyLogInstance | undefined {
  for (const ct of ctlogs) {
    const keyIdBytes = b64Decode(ct.logId.keyId);
    if (!bytesEqual(keyIdBytes, logID)) continue;
    if (timestamp && !isWithinValidFor(timestamp, ct.publicKey.validFor)) continue;
    return ct;
  }
  return undefined;
}

/** Check if a time falls within a validFor window */
function isWithinValidFor(time: Date, validFor: { start: string; end?: string }): boolean {
  if (time < new Date(validFor.start)) return false;
  if (validFor.end && time > new Date(validFor.end)) return false;
  return true;
}

// OID 2.5.29.15 = keyUsage
const OID_KEY_USAGE_LEAF = new Uint8Array([0x55, 0x1d, 0x0f]);
// OID 2.5.29.37 = extKeyUsage
const OID_EXT_KEY_USAGE = new Uint8Array([0x55, 0x1d, 0x25]);
// OID 1.3.6.1.5.5.7.3.3 = id-kp-codeSigning
const OID_CODE_SIGNING = new Uint8Array([0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03]);

/**
 * Check if a certificate has the CodeSigning EKU (1.3.6.1.5.5.7.3.3).
 * extKeyUsage ::= SEQUENCE OF OID
 * Returns false if the extension is absent or CodeSigning OID is not found.
 */
function hasCodeSigningEKU(tbs: Uint8Array): boolean {
  const extensions = extractExtensions(tbs);
  const ekuExt = findExtensionByOid(extensions, OID_EXT_KEY_USAGE);
  if (!ekuExt) return false; // EKU must be present on Fulcio certs

  // Parse SEQUENCE OF OID
  const seq = readTL(ekuExt.value, 0);
  if (seq.tag !== 0x30) return false;

  let offset = seq.headerSize;
  const end = seq.headerSize + seq.length;
  while (offset < end) {
    const oidTL = readTL(ekuExt.value, offset);
    if (oidTL.tag === 0x06) {
      const oid = ekuExt.value.subarray(offset + oidTL.headerSize, offset + oidTL.headerSize + oidTL.length);
      if (bytesEqual(oid, OID_CODE_SIGNING)) return true;
    }
    offset += oidTL.headerSize + oidTL.length;
  }
  return false;
}

/**
 * Check if a certificate has the digitalSignature bit set in keyUsage.
 * digitalSignature is bit 0 (MSB of first byte = 0x80).
 * Returns true if extension is absent (unconstrained) or bit is set.
 */
function hasDigitalSignatureUsage(tbs: Uint8Array): boolean {
  const extensions = extractExtensions(tbs);
  const kuExt = findExtensionByOid(extensions, OID_KEY_USAGE_LEAF);
  if (!kuExt) return true; // No keyUsage extension = unconstrained

  const bs = readTL(kuExt.value, 0);
  if (bs.tag !== 0x03 || bs.length < 2) return false;

  const byte0 = kuExt.value[bs.headerSize + 1];
  // digitalSignature is bit 0 (0x80 in first byte)
  return (byte0 & 0x80) !== 0;
}
