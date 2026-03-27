import { verifyCertSignature } from "../cert.ts";
import {
  derSignatureToRaw,
  detectSignatureAlgorithm,
  extractSerialNumber,
  extractSpki,
  hasKeyCertSignUsage,
  isCaCert,
  parseCertificate,
  readTL,
} from "../der.ts";
import { b64Decode, bytesEqual, serialsEqual } from "../util.ts";
import type { TrustedRoot } from "./types.ts";
import { SigstoreError } from "./types.ts";

// OID constants (pre-encoded DER bytes)
// 1.2.840.113549.1.9.4 = messageDigest
const OID_MESSAGE_DIGEST = new Uint8Array([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04]);
// 2.16.840.1.101.3.4.2.1 = SHA-256
const OID_SHA256 = new Uint8Array([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);
// 2.16.840.1.101.3.4.2.2 = SHA-384
const OID_SHA384 = new Uint8Array([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02]);
// Curve OIDs for SPKI detection
// 1.2.840.10045.3.1.7 = P-256
const OID_P256 = new Uint8Array([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);
// 1.3.132.0.34 = P-384
const OID_P384 = new Uint8Array([0x2b, 0x81, 0x04, 0x00, 0x22]);
// Signature algorithm OIDs
// 1.2.840.10045.4.3.2 = ecdsa-with-SHA256
const OID_ECDSA_SHA256 = new Uint8Array([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]);
// 1.2.840.10045.4.3.3 = ecdsa-with-SHA384
const OID_ECDSA_SHA384 = new Uint8Array([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03]);

/** Parsed CMS SignedData */
interface CMSSignedData {
  eContent: Uint8Array;
  certificates: Uint8Array[];
  signerInfo: CMSSignerInfo;
}

/** Parsed CMS SignerInfo */
interface CMSSignerInfo {
  issuerRaw: Uint8Array;
  serialNumber: Uint8Array;
  digestAlgOid: Uint8Array;
  signedAttrsRaw: Uint8Array; // raw bytes with 0xA0 tag
  sigAlgOid: Uint8Array;
  signature: Uint8Array;
}

/**
 * Verify RFC 3161 timestamp tokens and return verified signing times.
 *
 * For each CMS TimeStampToken:
 * 1. Parse CMS SignedData structure
 * 2. Find TSA signing cert (in embedded certs or trusted root)
 * 3. Verify TSA cert chains to a trusted timestamp authority
 * 4. Verify signedAttrs messageDigest == hash(eContent)
 * 5. Verify CMS signature over re-tagged signedAttrs
 * 6. Extract genTime from TSTInfo
 * 7. Verify TSTInfo messageImprint matches hash of artifact signature
 *
 * Returns only timestamps with verified CMS signatures.
 *
 * @param artifactSignature The DSSE envelope signature bytes that were timestamped.
 *   If provided, the TSTInfo messageImprint is verified against SHA-256(artifactSignature).
 */
export async function verifyRFC3161Timestamps(
  timestamps: Uint8Array[],
  trustedRoot: TrustedRoot,
  artifactSignature?: Uint8Array,
): Promise<Date[]> {
  const verifiedDates: Date[] = [];

  for (const ts of timestamps) {
    try {
      // 1. Parse CMS structure
      const cms = parseCMSSignedData(ts);

      // 2. Find and verify TSA signing cert
      const { certDer: tsaCertDer, validFor } = await findAndVerifyTSACert(cms, trustedRoot);

      // 3. Verify messageDigest attribute matches eContent hash
      await verifyMessageDigest(cms.signerInfo, cms.eContent);

      // 4. Verify CMS signature over signedAttrs
      await verifyCMSSignature(cms.signerInfo, tsaCertDer);

      // 5. Extract genTime from verified TSTInfo
      const date = parseTSTInfoGenTime(cms.eContent);
      if (!date) continue;

      // 6. Verify genTime falls within TSA authority's validFor window
      if (!isWithinValidFor(date, validFor)) continue;

      // 7. Verify messageImprint binds this timestamp to the artifact
      if (artifactSignature) {
        const bound = await verifyMessageImprint(cms.eContent, artifactSignature);
        if (!bound) continue;
      }

      verifiedDates.push(date);
    } catch {}
  }

  return verifiedDates;
}

/**
 * Parse CMS ContentInfo → SignedData.
 *
 * ContentInfo SEQUENCE {
 *   contentType OID (signedData)
 *   [0] SignedData SEQUENCE {
 *     version INTEGER
 *     digestAlgorithms SET
 *     encapContentInfo SEQUENCE { eContentType OID, [0] OCTET STRING { TSTInfo } }
 *     [0] IMPLICIT certificates (optional)
 *     signerInfos SET
 *   }
 * }
 */
function parseCMSSignedData(der: Uint8Array): CMSSignedData {
  // Outer ContentInfo SEQUENCE
  const outerTL = readTL(der, 0);
  let offset = outerTL.headerSize;

  // Skip contentType OID
  const oidTL = readTL(der, offset);
  offset += oidTL.headerSize + oidTL.length;

  // content [0] (tag 0xA0)
  const contentTL = readTL(der, offset);
  if (contentTL.tag !== 0xa0) {
    throw new SigstoreError("TIMESTAMP_ERROR", "CMS: expected [0] content wrapper");
  }
  offset += contentTL.headerSize;

  // SignedData SEQUENCE
  const sdTL = readTL(der, offset);
  if (sdTL.tag !== 0x30) {
    throw new SigstoreError("TIMESTAMP_ERROR", "CMS: expected SignedData SEQUENCE");
  }
  const sdEnd = offset + sdTL.headerSize + sdTL.length;
  let sdOffset = offset + sdTL.headerSize;

  // Skip version INTEGER
  const versionTL = readTL(der, sdOffset);
  sdOffset += versionTL.headerSize + versionTL.length;

  // Skip digestAlgorithms SET
  const daTL = readTL(der, sdOffset);
  sdOffset += daTL.headerSize + daTL.length;

  // encapsulatedContentInfo SEQUENCE
  const eciTL = readTL(der, sdOffset);
  if (eciTL.tag !== 0x30) {
    throw new SigstoreError("TIMESTAMP_ERROR", "CMS: expected encapContentInfo SEQUENCE");
  }
  const eciEnd = sdOffset + eciTL.headerSize + eciTL.length;
  let eciOffset = sdOffset + eciTL.headerSize;

  // Skip eContentType OID
  const eOidTL = readTL(der, eciOffset);
  eciOffset += eOidTL.headerSize + eOidTL.length;

  // eContent [0] (tag 0xA0)
  const eContentTL = readTL(der, eciOffset);
  if (eContentTL.tag !== 0xa0) {
    throw new SigstoreError("TIMESTAMP_ERROR", "CMS: expected [0] eContent wrapper");
  }
  eciOffset += eContentTL.headerSize;

  // OCTET STRING containing TSTInfo
  const octetTL = readTL(der, eciOffset);
  if (octetTL.tag !== 0x04) {
    throw new SigstoreError("TIMESTAMP_ERROR", "CMS: expected OCTET STRING for eContent");
  }
  const eContent = der.subarray(eciOffset + octetTL.headerSize, eciOffset + octetTL.headerSize + octetTL.length);

  // After encapContentInfo, look for optional certificates [0] and signerInfos SET
  sdOffset = eciEnd;
  const certificates: Uint8Array[] = [];

  // Optional certificates [0] (tag 0xA0) or CRLs [1] (tag 0xA1)
  if (sdOffset < sdEnd) {
    let tl = readTL(der, sdOffset);
    // Certificates [0] IMPLICIT — may be empty or contain concatenated cert SEQUENCEs
    if (tl.tag === 0xa0) {
      if (tl.length > 0) {
        let certPos = sdOffset + tl.headerSize;
        const certEnd = sdOffset + tl.headerSize + tl.length;
        while (certPos < certEnd) {
          const certTL = readTL(der, certPos);
          if (certTL.tag === 0x30) {
            certificates.push(der.subarray(certPos, certPos + certTL.headerSize + certTL.length));
          }
          certPos += certTL.headerSize + certTL.length;
        }
      }
      sdOffset += tl.headerSize + tl.length;
      if (sdOffset < sdEnd) tl = readTL(der, sdOffset);
    }
    // Skip optional CRLs [1]
    if (tl.tag === 0xa1) {
      sdOffset += tl.headerSize + tl.length;
    }
  }

  // signerInfos SET
  const siSetTL = readTL(der, sdOffset);
  if (siSetTL.tag !== 0x31) {
    throw new SigstoreError("TIMESTAMP_ERROR", "CMS: expected signerInfos SET");
  }

  // Parse first SignerInfo (RFC 3161 tokens have exactly one)
  const siOffset = sdOffset + siSetTL.headerSize;
  const signerInfo = parseCMSSignerInfo(der, siOffset);

  return { eContent, certificates, signerInfo };
}

/**
 * Parse a CMS SignerInfo structure.
 *
 * SignerInfo SEQUENCE {
 *   version INTEGER
 *   sid IssuerAndSerialNumber SEQUENCE { issuer Name, serialNumber INTEGER }
 *   digestAlgorithm AlgorithmIdentifier SEQUENCE
 *   signedAttrs [0] IMPLICIT SET OF Attribute
 *   signatureAlgorithm AlgorithmIdentifier SEQUENCE
 *   signature OCTET STRING
 * }
 */
function parseCMSSignerInfo(der: Uint8Array, offset: number): CMSSignerInfo {
  const siTL = readTL(der, offset);
  if (siTL.tag !== 0x30) {
    throw new SigstoreError("TIMESTAMP_ERROR", "CMS: expected SignerInfo SEQUENCE");
  }
  let pos = offset + siTL.headerSize;

  // version INTEGER
  const vTL = readTL(der, pos);
  pos += vTL.headerSize + vTL.length;

  // sid: IssuerAndSerialNumber SEQUENCE { issuer Name, serialNumber INTEGER }
  const sidTL = readTL(der, pos);
  if (sidTL.tag !== 0x30) {
    throw new SigstoreError("TIMESTAMP_ERROR", "CMS: expected IssuerAndSerialNumber SEQUENCE");
  }
  let sidPos = pos + sidTL.headerSize;

  // issuer Name (SEQUENCE)
  const issuerTL = readTL(der, sidPos);
  const issuerRaw = der.subarray(sidPos, sidPos + issuerTL.headerSize + issuerTL.length);
  sidPos += issuerTL.headerSize + issuerTL.length;

  // serialNumber INTEGER
  const serialTL = readTL(der, sidPos);
  const serialNumber = der.subarray(sidPos + serialTL.headerSize, sidPos + serialTL.headerSize + serialTL.length);
  pos += sidTL.headerSize + sidTL.length;

  // digestAlgorithm AlgorithmIdentifier SEQUENCE
  const daTL = readTL(der, pos);
  const digestAlgOid = extractOidFromAlgId(der, pos);
  pos += daTL.headerSize + daTL.length;

  // signedAttrs [0] IMPLICIT (tag 0xA0)
  const saTL = readTL(der, pos);
  if (saTL.tag !== 0xa0) {
    throw new SigstoreError("TIMESTAMP_ERROR", "CMS: expected signedAttrs [0]");
  }
  const signedAttrsRaw = der.subarray(pos, pos + saTL.headerSize + saTL.length);
  pos += saTL.headerSize + saTL.length;

  // signatureAlgorithm AlgorithmIdentifier SEQUENCE
  const saaTL = readTL(der, pos);
  const sigAlgOid = extractOidFromAlgId(der, pos);
  pos += saaTL.headerSize + saaTL.length;

  // signature OCTET STRING
  const sigTL = readTL(der, pos);
  if (sigTL.tag !== 0x04) {
    throw new SigstoreError("TIMESTAMP_ERROR", "CMS: expected signature OCTET STRING");
  }
  const signature = der.subarray(pos + sigTL.headerSize, pos + sigTL.headerSize + sigTL.length);

  return { issuerRaw, serialNumber, digestAlgOid, signedAttrsRaw, sigAlgOid, signature };
}

/** Extract the OID bytes from an AlgorithmIdentifier SEQUENCE */
function extractOidFromAlgId(der: Uint8Array, offset: number): Uint8Array {
  const seqTL = readTL(der, offset);
  const oidTL = readTL(der, offset + seqTL.headerSize);
  if (oidTL.tag !== 0x06) {
    throw new SigstoreError("TIMESTAMP_ERROR", "CMS: expected OID in AlgorithmIdentifier");
  }
  const start = offset + seqTL.headerSize + oidTL.headerSize;
  return der.subarray(start, start + oidTL.length);
}

/**
 * Find and verify the TSA signing certificate.
 *
 * 1. Look in CMS embedded certs first, then in trustedRoot.timestampAuthorities
 * 2. Match by issuer + serial number from SignerInfo
 * 3. Verify cert chain to trusted root
 *
 * Returns the cert DER and the matched authority's validFor window.
 */
async function findAndVerifyTSACert(
  cms: CMSSignedData,
  trustedRoot: TrustedRoot,
): Promise<{ certDer: Uint8Array; validFor: { start: string; end?: string } }> {
  const { signerInfo, certificates: embeddedCerts } = cms;

  // Collect candidate certs: embedded + all certs from trusted TSA authorities
  const candidates: { certDer: Uint8Array; authorityIndex: number }[] = [];

  // Embedded certs (authorityIndex -1 = not from trusted root)
  for (const cert of embeddedCerts) {
    candidates.push({ certDer: cert, authorityIndex: -1 });
  }

  // Certs from trusted root timestampAuthorities
  for (let i = 0; i < trustedRoot.timestampAuthorities.length; i++) {
    const tsa = trustedRoot.timestampAuthorities[i];
    for (const certEntry of tsa.certChain.certificates) {
      candidates.push({ certDer: b64Decode(certEntry.rawBytes), authorityIndex: i });
    }
  }

  // Find matching cert by issuer + serial
  for (const { certDer, authorityIndex } of candidates) {
    const cert = parseCertificate(certDer);
    const certIssuer = extractIssuerRaw(cert.tbs);
    const certSerial = extractSerialNumber(cert.tbs);

    if (bytesEqual(certIssuer, signerInfo.issuerRaw) && serialsEqual(certSerial, signerInfo.serialNumber)) {
      // Found matching cert — verify chain to trusted root
      let matchedValidFor: { start: string; end?: string };
      if (authorityIndex >= 0) {
        // Already from trusted root, verify its chain
        const authority = trustedRoot.timestampAuthorities[authorityIndex];
        await verifyTSACertChain(certDer, authority);
        matchedValidFor = authority.validFor;
      } else {
        // Embedded cert — must chain to some TSA authority
        let chainVerified = false;
        let foundValidFor: { start: string; end?: string } | undefined;
        for (const tsa of trustedRoot.timestampAuthorities) {
          try {
            await verifyTSACertChain(certDer, tsa);
            chainVerified = true;
            foundValidFor = tsa.validFor;
            break;
          } catch {
            /* try next */
          }
        }
        if (!chainVerified || !foundValidFor) {
          throw new SigstoreError("TIMESTAMP_ERROR", "TSA cert does not chain to any trusted timestamp authority");
        }
        matchedValidFor = foundValidFor;
      }
      return { certDer, validFor: matchedValidFor };
    }
  }

  throw new SigstoreError("TIMESTAMP_ERROR", "TSA signing cert not found (no cert matches SignerInfo issuer+serial)");
}

/**
 * Extract raw issuer Name bytes from a TBS certificate.
 * Walks to index 3 (issuer) assuming version [0] 0xA0 is present (v3 cert).
 */
function extractIssuerRaw(tbs: Uint8Array): Uint8Array {
  const tbsOuter = readTL(tbs, 0);
  let offset = tbsOuter.headerSize;

  // Walk to index 3: skip version[0], serial[1], sigAlg[2]
  for (let i = 0; i < 3; i++) {
    const tl = readTL(tbs, offset);
    offset += tl.headerSize + tl.length;
  }

  // Index 3 = issuer Name
  const issuerTL = readTL(tbs, offset);
  return tbs.subarray(offset, offset + issuerTL.headerSize + issuerTL.length);
}

/**
 * Verify a TSA cert chains to a trusted timestamp authority.
 * Follows the same pattern as Fulcio cert chain verification.
 */
async function verifyTSACertChain(
  tsaCertDer: Uint8Array,
  authority: TrustedRoot["timestampAuthorities"][0],
): Promise<void> {
  const certs = authority.certChain.certificates;
  if (certs.length === 0) {
    throw new SigstoreError("TIMESTAMP_ERROR", "TSA authority has empty cert chain");
  }

  const tsaCert = parseCertificate(tsaCertDer);

  if (certs.length === 1) {
    // Self-signed root: verify TSA cert directly
    const rootDer = b64Decode(certs[0].rawBytes);
    const rootCert = parseCertificate(rootDer);
    if (!isCaCert(rootCert.tbs) || !hasKeyCertSignUsage(rootCert.tbs)) {
      throw new SigstoreError("TIMESTAMP_ERROR", "TSA root cert is not a CA or lacks keyCertSign");
    }
    const rootSpki = extractSpki(rootCert.tbs);
    const algo = detectSignatureAlgorithm(tsaCert.signatureAlgorithm);
    const valid = await verifyCertSignature(rootSpki, tsaCert.tbs, tsaCert.signature, algo);
    if (!valid) {
      throw new SigstoreError("TIMESTAMP_ERROR", "TSA cert signature not verified by root");
    }
  } else {
    // Chain: leaf (first) + root (last)
    const leafDer = b64Decode(certs[0].rawBytes);
    const rootDer = b64Decode(certs[certs.length - 1].rawBytes);

    const rootCert = parseCertificate(rootDer);
    if (!isCaCert(rootCert.tbs) || !hasKeyCertSignUsage(rootCert.tbs)) {
      throw new SigstoreError("TIMESTAMP_ERROR", "TSA root cert is not a CA or lacks keyCertSign");
    }

    // Check if the TSA cert IS the leaf cert (matching by serial)
    const leafCert = parseCertificate(leafDer);
    const tsaSerial = extractSerialNumber(tsaCert.tbs);
    const leafSerial = extractSerialNumber(leafCert.tbs);

    if (serialsEqual(tsaSerial, leafSerial)) {
      // TSA cert is the leaf — verify root → leaf
      const rootSpki = extractSpki(rootCert.tbs);
      const algo = detectSignatureAlgorithm(leafCert.signatureAlgorithm);
      const valid = await verifyCertSignature(rootSpki, leafCert.tbs, leafCert.signature, algo);
      if (!valid) {
        throw new SigstoreError("TIMESTAMP_ERROR", "TSA leaf cert not signed by root");
      }
    } else {
      // TSA cert is external — verify root → intermediate → TSA
      if (!isCaCert(leafCert.tbs) || !hasKeyCertSignUsage(leafCert.tbs)) {
        throw new SigstoreError("TIMESTAMP_ERROR", "TSA intermediate cert is not a CA or lacks keyCertSign");
      }
      const rootSpki = extractSpki(rootCert.tbs);
      const intAlgo = detectSignatureAlgorithm(leafCert.signatureAlgorithm);
      const intValid = await verifyCertSignature(rootSpki, leafCert.tbs, leafCert.signature, intAlgo);
      if (!intValid) {
        throw new SigstoreError("TIMESTAMP_ERROR", "TSA intermediate cert not signed by root");
      }
      const intSpki = extractSpki(leafCert.tbs);
      const tsaAlgo = detectSignatureAlgorithm(tsaCert.signatureAlgorithm);
      const tsaValid = await verifyCertSignature(intSpki, tsaCert.tbs, tsaCert.signature, tsaAlgo);
      if (!tsaValid) {
        throw new SigstoreError("TIMESTAMP_ERROR", "TSA cert not signed by intermediate");
      }
    }
  }
}

/**
 * Verify the messageDigest signed attribute matches hash(eContent).
 */
async function verifyMessageDigest(signerInfo: CMSSignerInfo, eContent: Uint8Array): Promise<void> {
  const hashName = detectHashAlgorithm(signerInfo.digestAlgOid);
  const digest = new Uint8Array(await crypto.subtle.digest(hashName, eContent));
  const messageDigest = extractMessageDigestAttr(signerInfo.signedAttrsRaw);

  if (!bytesEqual(digest, messageDigest)) {
    throw new SigstoreError("TIMESTAMP_ERROR", "CMS messageDigest attribute does not match eContent hash");
  }
}

/**
 * Find the messageDigest attribute value in signedAttrs.
 *
 * signedAttrs is [0] IMPLICIT SET OF Attribute (tag 0xA0).
 * Each Attribute: SEQUENCE { OID, SET { value } }
 */
function extractMessageDigestAttr(signedAttrsRaw: Uint8Array): Uint8Array {
  const outerTL = readTL(signedAttrsRaw, 0);
  let offset = outerTL.headerSize;
  const end = outerTL.headerSize + outerTL.length;

  while (offset < end) {
    const attrTL = readTL(signedAttrsRaw, offset);
    const attrEnd = offset + attrTL.headerSize + attrTL.length;
    let pos = offset + attrTL.headerSize;

    // OID
    const oidTL = readTL(signedAttrsRaw, pos);
    if (oidTL.tag === 0x06) {
      const oid = signedAttrsRaw.subarray(pos + oidTL.headerSize, pos + oidTL.headerSize + oidTL.length);
      if (bytesEqual(oid, OID_MESSAGE_DIGEST)) {
        // Found messageDigest — value is in the SET
        pos += oidTL.headerSize + oidTL.length;
        const setTL = readTL(signedAttrsRaw, pos);
        pos += setTL.headerSize;
        // OCTET STRING value inside the SET
        const valTL = readTL(signedAttrsRaw, pos);
        if (valTL.tag !== 0x04) {
          throw new SigstoreError("TIMESTAMP_ERROR", "messageDigest value is not OCTET STRING");
        }
        return signedAttrsRaw.subarray(pos + valTL.headerSize, pos + valTL.headerSize + valTL.length);
      }
    }

    offset = attrEnd;
  }

  throw new SigstoreError("TIMESTAMP_ERROR", "messageDigest attribute not found in signedAttrs");
}

/**
 * Verify the CMS signature over the re-tagged signedAttrs.
 *
 * Per RFC 5652 section 5.4: the signature is computed over the DER encoding
 * of signedAttrs with the IMPLICIT [0] tag (0xA0) replaced by SET (0x31).
 */
async function verifyCMSSignature(signerInfo: CMSSignerInfo, tsaCertDer: Uint8Array): Promise<void> {
  // Re-tag signedAttrs: 0xA0 → 0x31
  const retagged = new Uint8Array(signerInfo.signedAttrsRaw);
  retagged[0] = 0x31;

  // Detect hash from signatureAlgorithm OID
  const hashName = detectSigHash(signerInfo.sigAlgOid);

  // Import TSA cert's public key
  const tsaCert = parseCertificate(tsaCertDer);
  const spki = extractSpki(tsaCert.tbs);
  const { curve, componentSize } = detectCurveFromSpki(spki);

  const key = await crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: curve }, false, ["verify"]);

  // Convert DER ECDSA signature to raw r||s
  const rawSig = derSignatureToRaw(signerInfo.signature, componentSize);

  const valid = await crypto.subtle.verify({ name: "ECDSA", hash: hashName }, key, rawSig, retagged);

  if (!valid) {
    throw new SigstoreError("TIMESTAMP_ERROR", "CMS signature verification failed");
  }
}

/** Detect hash algorithm name from digest algorithm OID */
function detectHashAlgorithm(oid: Uint8Array): string {
  if (bytesEqual(oid, OID_SHA256)) return "SHA-256";
  if (bytesEqual(oid, OID_SHA384)) return "SHA-384";
  throw new SigstoreError("TIMESTAMP_ERROR", `Unsupported digest algorithm OID`);
}

/** Detect hash algorithm from ECDSA signature algorithm OID */
function detectSigHash(oid: Uint8Array): string {
  if (bytesEqual(oid, OID_ECDSA_SHA256)) return "SHA-256";
  if (bytesEqual(oid, OID_ECDSA_SHA384)) return "SHA-384";
  throw new SigstoreError("TIMESTAMP_ERROR", `Unsupported signature algorithm OID`);
}

/** Detect EC curve and component size from SPKI bytes */
function detectCurveFromSpki(spki: Uint8Array): { curve: string; componentSize: number } {
  if (containsBytes(spki, OID_P384)) return { curve: "P-384", componentSize: 48 };
  if (containsBytes(spki, OID_P256)) return { curve: "P-256", componentSize: 32 };
  throw new SigstoreError("TIMESTAMP_ERROR", "Unsupported EC curve in TSA cert SPKI");
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

/** Check if a time falls within a validFor window */
function isWithinValidFor(time: Date, validFor: { start: string; end?: string }): boolean {
  if (time < new Date(validFor.start)) return false;
  if (validFor.end && time > new Date(validFor.end)) return false;
  return true;
}

/**
 * Verify TSTInfo messageImprint matches SHA-256(artifactSignature).
 *
 * TSTInfo SEQUENCE { version, policy, messageImprint SEQUENCE { hashAlg, hashedMessage }, ... }
 * messageImprint.hashedMessage must equal the hash of the artifact being timestamped.
 * In Sigstore, the artifact is the DSSE envelope signature bytes.
 */
async function verifyMessageImprint(tstInfo: Uint8Array, artifactSignature: Uint8Array): Promise<boolean> {
  const outerTL = readTL(tstInfo, 0);
  if (outerTL.tag !== 0x30) return false;

  let offset = outerTL.headerSize;

  // Skip: version (INTEGER), policy (OID)
  for (let i = 0; i < 2 && offset < tstInfo.length; i++) {
    const tl = readTL(tstInfo, offset);
    offset += tl.headerSize + tl.length;
  }

  // messageImprint SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }
  if (offset >= tstInfo.length) return false;
  const miTL = readTL(tstInfo, offset);
  if (miTL.tag !== 0x30) return false;

  let miOffset = offset + miTL.headerSize;

  // hashAlgorithm (AlgorithmIdentifier SEQUENCE)
  const algTL = readTL(tstInfo, miOffset);
  miOffset += algTL.headerSize + algTL.length;

  // hashedMessage (OCTET STRING)
  if (miOffset >= offset + miTL.headerSize + miTL.length) return false;
  const hashTL = readTL(tstInfo, miOffset);
  if (hashTL.tag !== 0x04) return false;
  const hashedMessage = tstInfo.subarray(miOffset + hashTL.headerSize, miOffset + hashTL.headerSize + hashTL.length);

  // Compute SHA-256 of the artifact signature and compare
  const expectedHash = new Uint8Array(await crypto.subtle.digest("SHA-256", artifactSignature));
  return bytesEqual(hashedMessage, expectedHash);
}

// --- TSTInfo genTime extraction (retained from original) ---

/**
 * Parse TSTInfo and extract genTime.
 * TSTInfo SEQUENCE { version, policy, messageImprint, serialNumber, genTime, ... }
 */
function parseTSTInfoGenTime(tstInfo: Uint8Array): Date | null {
  const outerTL = readTL(tstInfo, 0);
  if (outerTL.tag !== 0x30) return null;

  let offset = outerTL.headerSize;

  // Skip: version (INTEGER), policy (OID), messageImprint (SEQUENCE), serialNumber (INTEGER)
  for (let i = 0; i < 4 && offset < tstInfo.length; i++) {
    const tl = readTL(tstInfo, offset);
    offset += tl.headerSize + tl.length;
  }

  // genTime should be GeneralizedTime (tag 0x18)
  if (offset >= tstInfo.length) return null;
  const timeTL = readTL(tstInfo, offset);
  if (timeTL.tag !== 0x18) return null;

  const timeStr = new TextDecoder().decode(
    tstInfo.subarray(offset + timeTL.headerSize, offset + timeTL.headerSize + timeTL.length),
  );

  return parseGeneralizedTime(timeStr);
}

function parseGeneralizedTime(s: string): Date {
  const year = parseInt(s.slice(0, 4), 10);
  const month = parseInt(s.slice(4, 6), 10) - 1;
  const day = parseInt(s.slice(6, 8), 10);
  const hour = parseInt(s.slice(8, 10), 10);
  const min = parseInt(s.slice(10, 12), 10);
  const sec = parseInt(s.slice(12, 14), 10);

  let ms = 0;
  if (s[14] === ".") {
    const fracEnd = s.indexOf("Z", 14);
    const frac = s.slice(15, fracEnd);
    ms = parseInt(frac.padEnd(3, "0").slice(0, 3), 10);
  }

  return new Date(Date.UTC(year, month, day, hour, min, sec, ms));
}
