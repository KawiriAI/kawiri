import { bytesEqual } from "./util.ts";

/** Parsed TLV (Tag-Length-Value) header */
export interface TLHeader {
  tag: number;
  length: number;
  headerSize: number;
}

/** Read a DER tag and length at the given offset */
export function readTL(buf: Uint8Array, offset: number): TLHeader {
  if (offset + 1 >= buf.length) {
    throw new Error(`DER: offset ${offset} out of bounds (length ${buf.length})`);
  }

  const tag = buf[offset];
  let length: number;
  let headerSize: number;

  const lenByte = buf[offset + 1];
  if (lenByte < 0x80) {
    length = lenByte;
    headerSize = 2;
  } else if (lenByte === 0x81) {
    if (offset + 2 >= buf.length) throw new Error("DER: truncated length (0x81)");
    length = buf[offset + 2];
    headerSize = 3;
  } else if (lenByte === 0x82) {
    if (offset + 3 >= buf.length) throw new Error("DER: truncated length (0x82)");
    length = (buf[offset + 2] << 8) | buf[offset + 3];
    headerSize = 4;
  } else if (lenByte === 0x83) {
    if (offset + 4 >= buf.length) throw new Error("DER: truncated length (0x83)");
    length = (buf[offset + 2] << 16) | (buf[offset + 3] << 8) | buf[offset + 4];
    headerSize = 5;
  } else {
    throw new Error(`DER: unsupported length encoding 0x${lenByte.toString(16)}`);
  }

  // Bounds check: ensure the TLV doesn't extend past the buffer
  if (offset + headerSize + length > buf.length) {
    throw new Error(
      `DER: TLV at offset ${offset} extends beyond buffer (need ${offset + headerSize + length}, have ${buf.length})`,
    );
  }

  return { tag, length, headerSize };
}

/** Parsed X.509 certificate structure */
export interface ParsedCertificate {
  /** Raw TBS bytes (including SEQUENCE tag+length) — the data that is signed */
  tbs: Uint8Array;
  /** Signature algorithm (SEQUENCE) */
  signatureAlgorithm: Uint8Array;
  /** Signature value (BIT STRING contents after the unused-bits byte) */
  signature: Uint8Array;
}

/**
 * Parse an X.509 DER certificate into its three top-level components:
 * [0] tbsCertificate, [1] signatureAlgorithm, [2] signatureValue
 */
export function parseCertificate(der: Uint8Array): ParsedCertificate {
  // Outer SEQUENCE
  const outer = readTL(der, 0);
  if (outer.tag !== 0x30) {
    throw new Error(`DER: expected SEQUENCE (0x30), got 0x${outer.tag.toString(16)}`);
  }

  let offset = outer.headerSize;

  // [0] tbsCertificate (SEQUENCE)
  const tbsTL = readTL(der, offset);
  const tbsEnd = offset + tbsTL.headerSize + tbsTL.length;
  const tbs = der.subarray(offset, tbsEnd);
  offset = tbsEnd;

  // [1] signatureAlgorithm (SEQUENCE)
  const sigAlgTL = readTL(der, offset);
  const sigAlgEnd = offset + sigAlgTL.headerSize + sigAlgTL.length;
  const signatureAlgorithm = der.subarray(offset, sigAlgEnd);
  offset = sigAlgEnd;

  // [2] signatureValue (BIT STRING)
  const sigValTL = readTL(der, offset);
  if (sigValTL.tag !== 0x03) {
    throw new Error(`DER: expected BIT STRING (0x03), got 0x${sigValTL.tag.toString(16)}`);
  }
  // Skip the unused-bits byte (should be 0x00)
  const sigStart = offset + sigValTL.headerSize + 1;
  const sigEnd = offset + sigValTL.headerSize + sigValTL.length;
  const signature = der.subarray(sigStart, sigEnd);

  return { tbs, signatureAlgorithm, signature };
}

/**
 * Extract SubjectPublicKeyInfo (SPKI) from a tbsCertificate.
 *
 * X.509v3 TBS structure:
 *   SEQUENCE {
 *     [0] version (context tag 0xA0) — optional but present in v3
 *     [1] serialNumber (INTEGER)
 *     [2] signatureAlgorithm (SEQUENCE)
 *     [3] issuer (SEQUENCE)
 *     [4] validity (SEQUENCE)
 *     [5] subject (SEQUENCE)
 *     [6] subjectPublicKeyInfo (SEQUENCE) <- this is what we want
 *     ...
 *   }
 */
export function extractSpki(tbs: Uint8Array): Uint8Array {
  // The tbs includes its own SEQUENCE tag+length, step inside
  const tbsOuter = readTL(tbs, 0);
  if (tbsOuter.tag !== 0x30) {
    throw new Error(`DER: TBS is not a SEQUENCE`);
  }

  let offset = tbsOuter.headerSize;
  let elementIndex = 0;
  const spkiIndex = 6; // SPKI is the 7th element (index 6) when version tag 0xA0 is present

  while (offset < tbs.length && elementIndex <= spkiIndex) {
    const tl = readTL(tbs, offset);
    const elementEnd = offset + tl.headerSize + tl.length;

    if (elementIndex === spkiIndex) {
      return tbs.subarray(offset, elementEnd);
    }

    offset = elementEnd;
    elementIndex++;
  }

  throw new Error("DER: could not find SPKI in TBS certificate");
}

// OID 2.5.4.3 = id-at-commonName
const OID_CN = new Uint8Array([0x55, 0x04, 0x03]);

/**
 * Extract the issuer Common Name (CN) from a TBS certificate.
 * The issuer is at index 3 in the TBS SEQUENCE (when version 0xA0 is present).
 *
 * Name = SEQUENCE OF RelativeDistinguishedName
 * RDN = SET OF AttributeTypeAndValue
 * ATV = SEQUENCE { OID, ANY (string) }
 */
export function extractIssuerCN(tbs: Uint8Array): string {
  const tbsOuter = readTL(tbs, 0);
  if (tbsOuter.tag !== 0x30) throw new Error("DER: TBS is not a SEQUENCE");

  let offset = tbsOuter.headerSize;
  let index = 0;
  const issuerIndex = 3; // issuer at index 3 when 0xA0 version present

  while (offset < tbs.length && index <= issuerIndex) {
    const tl = readTL(tbs, offset);
    const elementEnd = offset + tl.headerSize + tl.length;

    if (index === issuerIndex) {
      return extractCNFromName(tbs.subarray(offset, elementEnd));
    }

    offset = elementEnd;
    index++;
  }

  throw new Error("DER: could not find issuer in TBS certificate");
}

/** Extract CN from a Name SEQUENCE */
function extractCNFromName(nameBytes: Uint8Array): string {
  const outer = readTL(nameBytes, 0);
  if (outer.tag !== 0x30) throw new Error("DER: Name is not a SEQUENCE");

  let offset = outer.headerSize;
  const end = outer.headerSize + outer.length;

  while (offset < end) {
    // Each RDN is a SET
    const setTL = readTL(nameBytes, offset);
    const setEnd = offset + setTL.headerSize + setTL.length;
    let setPos = offset + setTL.headerSize;

    while (setPos < setEnd) {
      // ATV is a SEQUENCE { OID, value }
      const atvTL = readTL(nameBytes, setPos);
      const atvEnd = setPos + atvTL.headerSize + atvTL.length;
      let atvPos = setPos + atvTL.headerSize;

      const oidTL = readTL(nameBytes, atvPos);
      const oid = nameBytes.subarray(atvPos + oidTL.headerSize, atvPos + oidTL.headerSize + oidTL.length);
      atvPos += oidTL.headerSize + oidTL.length;

      if (bytesEqual(oid, OID_CN)) {
        // Value is a string (UTF8String, PrintableString, etc.)
        const valTL = readTL(nameBytes, atvPos);
        return new TextDecoder().decode(
          nameBytes.subarray(atvPos + valTL.headerSize, atvPos + valTL.headerSize + valTL.length),
        );
      }

      setPos = atvEnd;
    }

    offset = setEnd;
  }

  throw new Error("DER: CN not found in Name");
}

/**
 * Convert a DER-encoded ECDSA signature to raw r||s format for WebCrypto.
 *
 * DER: SEQUENCE { INTEGER r, INTEGER s }
 * Raw: r (componentSize bytes, zero-padded) || s (componentSize bytes, zero-padded)
 *
 * DER INTEGERs may have a leading 0x00 if the high bit is set, or be shorter than componentSize.
 */
export function derSignatureToRaw(derSig: Uint8Array, componentSize: number = 32): Uint8Array {
  // SEQUENCE tag
  const seqTL = readTL(derSig, 0);
  if (seqTL.tag !== 0x30) {
    throw new Error(`DER sig: expected SEQUENCE, got 0x${seqTL.tag.toString(16)}`);
  }

  let offset = seqTL.headerSize;

  // INTEGER r
  const rTL = readTL(derSig, offset);
  if (rTL.tag !== 0x02) {
    throw new Error(`DER sig: expected INTEGER for r, got 0x${rTL.tag.toString(16)}`);
  }
  offset += rTL.headerSize;
  const rRaw = derSig.subarray(offset, offset + rTL.length);
  offset += rTL.length;

  // INTEGER s
  const sTL = readTL(derSig, offset);
  if (sTL.tag !== 0x02) {
    throw new Error(`DER sig: expected INTEGER for s, got 0x${sTL.tag.toString(16)}`);
  }
  offset += sTL.headerSize;
  const sRaw = derSig.subarray(offset, offset + sTL.length);

  // Convert each component to fixed-size, stripping leading zeros or zero-padding
  const result = new Uint8Array(componentSize * 2);
  copyIntegerToFixed(rRaw, result, 0, componentSize);
  copyIntegerToFixed(sRaw, result, componentSize, componentSize);

  return result;
}

/** Copy a DER INTEGER value into a fixed-size field, handling leading 0x00 and padding */
function copyIntegerToFixed(src: Uint8Array, dest: Uint8Array, destOffset: number, size: number): void {
  // Strip leading zeros from DER encoding
  let srcStart = 0;
  while (srcStart < src.length - 1 && src[srcStart] === 0) {
    srcStart++;
  }
  const trimmed = src.length - srcStart;

  if (trimmed > size) {
    throw new Error(`DER INTEGER too large: ${trimmed} bytes, expected at most ${size}`);
  }

  // Right-align in the destination
  const padLen = size - trimmed;
  dest.set(src.subarray(srcStart), destOffset + padLen);
}

// --- Signature algorithm detection ---

/** Supported signature algorithm types */
export type SignatureAlgorithm = "ecdsa-p256-sha256" | "ecdsa-p384-sha384" | "rsa-pss-sha384";

// OID byte representations
const OID_RSASSA_PSS = new Uint8Array([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a]);
const OID_ECDSA_SHA256 = new Uint8Array([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]);
const OID_ECDSA_SHA384 = new Uint8Array([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03]);

/** Detect which algorithm signed this certificate by matching OID bytes in signatureAlgorithm */
export function detectSignatureAlgorithm(sigAlgBytes: Uint8Array): SignatureAlgorithm {
  // sigAlgBytes is a SEQUENCE containing the algorithm OID
  const seq = readTL(sigAlgBytes, 0);
  if (seq.tag !== 0x30) {
    throw new Error("DER: expected SEQUENCE for signatureAlgorithm");
  }

  const oidTL = readTL(sigAlgBytes, seq.headerSize);
  if (oidTL.tag !== 0x06) {
    throw new Error("DER: expected OID in signatureAlgorithm");
  }

  const oidStart = seq.headerSize + oidTL.headerSize;
  const oidBytes = sigAlgBytes.subarray(oidStart, oidStart + oidTL.length);

  if (bytesEqual(oidBytes, OID_RSASSA_PSS)) return "rsa-pss-sha384";
  if (bytesEqual(oidBytes, OID_ECDSA_SHA256)) return "ecdsa-p256-sha256";
  if (bytesEqual(oidBytes, OID_ECDSA_SHA384)) return "ecdsa-p384-sha384";

  const hex = Array.from(oidBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join(" ");
  throw new Error(`DER: unknown signature algorithm OID: ${hex}`);
}

// --- Certificate validity extraction ---

/** Certificate validity period */
export interface CertValidity {
  notBefore: Date;
  notAfter: Date;
}

/** Extract the validity period from a tbsCertificate */
export function extractValidity(tbs: Uint8Array): CertValidity {
  const tbsOuter = readTL(tbs, 0);
  if (tbsOuter.tag !== 0x30) {
    throw new Error("DER: TBS is not a SEQUENCE");
  }

  let offset = tbsOuter.headerSize;
  let index = 0;
  const validityIndex = 4; // index 4 when version 0xA0 present

  while (offset < tbs.length && index <= validityIndex) {
    const tl = readTL(tbs, offset);
    const end = offset + tl.headerSize + tl.length;

    if (index === validityIndex) {
      // Parse validity SEQUENCE { notBefore, notAfter }
      const seqTL = readTL(tbs, offset);
      let pos = offset + seqTL.headerSize;

      const nbTL = readTL(tbs, pos);
      const notBefore = parseAsn1Time(
        tbs.subarray(pos + nbTL.headerSize, pos + nbTL.headerSize + nbTL.length),
        nbTL.tag,
      );
      pos += nbTL.headerSize + nbTL.length;

      const naTL = readTL(tbs, pos);
      const notAfter = parseAsn1Time(
        tbs.subarray(pos + naTL.headerSize, pos + naTL.headerSize + naTL.length),
        naTL.tag,
      );

      return { notBefore, notAfter };
    }

    offset = end;
    index++;
  }

  throw new Error("DER: could not find validity in TBS certificate");
}

// --- X.509 Extension parsing ---

/** A parsed X.509v3 extension */
export interface X509Extension {
  /** OID bytes (raw, without tag+length) */
  oid: Uint8Array;
  /** Whether the extension is marked critical */
  critical: boolean;
  /** Extension value (OCTET STRING contents) */
  value: Uint8Array;
}

/**
 * Iterate the children of a DER SEQUENCE, yielding offset/tag/length/headerSize
 * for each child element.
 */
export function* iterateSequenceChildren(
  seq: Uint8Array,
): Generator<{ offset: number; tag: number; length: number; headerSize: number }> {
  const outer = readTL(seq, 0);
  if (outer.tag !== 0x30) {
    throw new Error(`DER: expected SEQUENCE (0x30), got 0x${outer.tag.toString(16)}`);
  }
  let offset = outer.headerSize;
  const end = outer.headerSize + outer.length;
  while (offset < end) {
    const tl = readTL(seq, offset);
    yield { offset, tag: tl.tag, length: tl.length, headerSize: tl.headerSize };
    offset += tl.headerSize + tl.length;
  }
}

/**
 * Extract X.509v3 extensions from a TBS certificate.
 *
 * Looks for the context tag [3] (0xA3) which wraps a SEQUENCE OF Extension.
 * Each Extension is SEQUENCE { OID, BOOLEAN critical (optional), OCTET STRING value }.
 */
export function extractExtensions(tbs: Uint8Array): X509Extension[] {
  const tbsOuter = readTL(tbs, 0);
  if (tbsOuter.tag !== 0x30) {
    throw new Error("DER: TBS is not a SEQUENCE");
  }

  // Walk TBS children to find tag 0xA3 (context [3] = extensions)
  let offset = tbsOuter.headerSize;
  while (offset < tbs.length) {
    const tl = readTL(tbs, offset);
    const elementEnd = offset + tl.headerSize + tl.length;

    if (tl.tag === 0xa3) {
      // Found extensions wrapper — contents is a SEQUENCE OF Extension
      const extSeqBytes = tbs.subarray(offset + tl.headerSize, elementEnd);
      return parseExtensionsSequence(extSeqBytes);
    }

    offset = elementEnd;
  }

  return []; // No extensions found (v1 cert)
}

function parseExtensionsSequence(data: Uint8Array): X509Extension[] {
  // data starts with a SEQUENCE wrapping all extensions
  const outer = readTL(data, 0);
  if (outer.tag !== 0x30) {
    throw new Error("DER: extensions wrapper is not a SEQUENCE");
  }

  const extensions: X509Extension[] = [];
  let offset = outer.headerSize;
  const end = outer.headerSize + outer.length;

  while (offset < end) {
    // Each extension is a SEQUENCE { OID, [BOOLEAN critical], OCTET STRING value }
    const extSeqTL = readTL(data, offset);
    if (extSeqTL.tag !== 0x30) {
      throw new Error("DER: extension is not a SEQUENCE");
    }

    const extEnd = offset + extSeqTL.headerSize + extSeqTL.length;
    let pos = offset + extSeqTL.headerSize;

    // OID
    const oidTL = readTL(data, pos);
    if (oidTL.tag !== 0x06) {
      throw new Error("DER: expected OID in extension");
    }
    const oid = data.subarray(pos + oidTL.headerSize, pos + oidTL.headerSize + oidTL.length);
    pos += oidTL.headerSize + oidTL.length;

    // Optional BOOLEAN critical (tag 0x01)
    let critical = false;
    if (pos < extEnd) {
      const nextTL = readTL(data, pos);
      if (nextTL.tag === 0x01) {
        critical = data[pos + nextTL.headerSize] !== 0;
        pos += nextTL.headerSize + nextTL.length;
      }
    }

    // OCTET STRING value
    const valTL = readTL(data, pos);
    if (valTL.tag !== 0x04) {
      throw new Error("DER: expected OCTET STRING for extension value");
    }
    const value = data.subarray(pos + valTL.headerSize, pos + valTL.headerSize + valTL.length);

    extensions.push({ oid, critical, value });
    offset = extEnd;
  }

  return extensions;
}

/**
 * Find an extension by its OID bytes.
 */
export function findExtensionByOid(extensions: X509Extension[], oid: Uint8Array): X509Extension | undefined {
  return extensions.find((ext) => bytesEqual(ext.oid, oid));
}

/**
 * Decode a UTF8String or IA5String from extension value bytes.
 * Strips the outer string tag+length and returns the decoded text.
 */
export function decodeStringExtension(ext: X509Extension): string {
  const tl = readTL(ext.value, 0);
  // Accept UTF8String (0x0C), IA5String (0x16), PrintableString (0x13)
  if (tl.tag !== 0x0c && tl.tag !== 0x16 && tl.tag !== 0x13) {
    throw new Error(`DER: expected string type, got 0x${tl.tag.toString(16)}`);
  }
  return new TextDecoder().decode(ext.value.subarray(tl.headerSize, tl.headerSize + tl.length));
}

// OID 2.5.29.19 = basicConstraints
const OID_BASIC_CONSTRAINTS = new Uint8Array([0x55, 0x1d, 0x13]);
// OID 2.5.29.15 = keyUsage
const OID_KEY_USAGE = new Uint8Array([0x55, 0x1d, 0x0f]);

/**
 * Check if a certificate has basicConstraints CA=true.
 * Returns true if the extension is present and cA is true.
 */
export function isCaCert(tbs: Uint8Array): boolean {
  const extensions = extractExtensions(tbs);
  const bcExt = findExtensionByOid(extensions, OID_BASIC_CONSTRAINTS);
  if (!bcExt) return false;

  // basicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER OPTIONAL }
  const seq = readTL(bcExt.value, 0);
  if (seq.tag !== 0x30) return false;

  // Empty sequence means CA=false (the default)
  if (seq.length === 0) return false;

  // First element should be BOOLEAN (tag 0x01)
  const firstTL = readTL(bcExt.value, seq.headerSize);
  if (firstTL.tag !== 0x01) return false;
  return bcExt.value[seq.headerSize + firstTL.headerSize] !== 0;
}

/**
 * Check if a certificate has the keyCertSign bit set in keyUsage.
 * keyUsage is a BIT STRING with bit 5 = keyCertSign.
 * Returns true if the extension is present and the bit is set,
 * or if the extension is absent (no constraint).
 */
export function hasKeyCertSignUsage(tbs: Uint8Array): boolean {
  const extensions = extractExtensions(tbs);
  const kuExt = findExtensionByOid(extensions, OID_KEY_USAGE);
  if (!kuExt) return true; // No keyUsage extension = unconstrained

  // keyUsage ::= BIT STRING
  const bs = readTL(kuExt.value, 0);
  if (bs.tag !== 0x03 || bs.length < 2) return false;

  const _unusedBits = kuExt.value[bs.headerSize];
  const byte0 = kuExt.value[bs.headerSize + 1];
  // keyCertSign is bit 5 (0-indexed from MSB): byte0 bit 2 (0x04)
  return (byte0 & 0x04) !== 0;
}

/**
 * Extract the serial number INTEGER from a TBS certificate.
 * Returns raw INTEGER bytes (no tag/length, may have leading zero).
 */
export function extractSerialNumber(tbs: Uint8Array): Uint8Array {
  const tbsOuter = readTL(tbs, 0);
  if (tbsOuter.tag !== 0x30) {
    throw new Error("DER: TBS is not a SEQUENCE");
  }

  let offset = tbsOuter.headerSize;

  // Skip version tag [0] (0xA0) if present
  const firstTL = readTL(tbs, offset);
  if (firstTL.tag === 0xa0) {
    offset += firstTL.headerSize + firstTL.length;
  }

  // Next is serialNumber (INTEGER, tag 0x02)
  const serialTL = readTL(tbs, offset);
  if (serialTL.tag !== 0x02) {
    throw new Error(`DER: expected INTEGER for serial number, got 0x${serialTL.tag.toString(16)}`);
  }

  return tbs.subarray(offset + serialTL.headerSize, offset + serialTL.headerSize + serialTL.length);
}

// --- OID decoding ---

/**
 * Decode raw DER OID bytes to dot-notation string.
 * First byte: first = floor(byte/40), second = byte%40.
 * Remaining: base-128 variable-length decoded.
 */
export function decodeOid(bytes: Uint8Array): string {
  if (bytes.length === 0) return "";

  const parts: number[] = [];
  parts.push(Math.floor(bytes[0] / 40));
  parts.push(bytes[0] % 40);

  let value = 0;
  for (let i = 1; i < bytes.length; i++) {
    value = (value << 7) | (bytes[i] & 0x7f);
    if ((bytes[i] & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }

  return parts.join(".");
}

// --- SCT parsing ---

/** Signed Certificate Timestamp (parsed from CT extension) */
export interface ParsedSCT {
  version: number;
  logID: Uint8Array;
  timestamp: bigint;
  extensions: Uint8Array;
  hashAlgorithm: number;
  signatureAlgorithm: number;
  signature: Uint8Array;
}

/**
 * Parse SCT list from a Certificate Transparency extension value.
 *
 * The extension value wraps an OCTET STRING containing TLS-encoded SCT list:
 * uint16 total length, then for each SCT: uint16 length + SCT bytes.
 * Each SCT: version(1) + logID(32) + timestamp(8) + extensions_len(2) + extensions + hash_algo(1) + sig_algo(1) + sig_len(2) + signature.
 */
export function parseSctList(extValue: Uint8Array): ParsedSCT[] {
  // The extension value may be wrapped in an OCTET STRING
  let data = extValue;
  const tl = readTL(data, 0);
  if (tl.tag === 0x04) {
    data = data.subarray(tl.headerSize, tl.headerSize + tl.length);
  }

  // TLS-encoded SCT list: uint16 total length
  if (data.length < 2) return [];
  const totalLen = (data[0] << 8) | data[1];
  let offset = 2;
  const end = 2 + totalLen;

  const scts: ParsedSCT[] = [];

  while (offset < end && offset < data.length) {
    // uint16 SCT length
    const sctLen = (data[offset] << 8) | data[offset + 1];
    offset += 2;

    const sctEnd = offset + sctLen;
    if (sctEnd > data.length) break;

    // Parse individual SCT
    const version = data[offset];
    offset += 1;
    const logID = data.subarray(offset, offset + 32);
    offset += 32;

    // timestamp: uint64 (milliseconds since epoch)
    let ts = 0n;
    for (let i = 0; i < 8; i++) {
      ts = (ts << 8n) | BigInt(data[offset + i]);
    }
    offset += 8;

    // extensions: uint16 length + data
    const extLen = (data[offset] << 8) | data[offset + 1];
    offset += 2;
    const extensions = data.subarray(offset, offset + extLen);
    offset += extLen;

    // hash algorithm (1 byte) + signature algorithm (1 byte)
    const hashAlgorithm = data[offset];
    offset += 1;
    const signatureAlgorithm = data[offset];
    offset += 1;

    // signature: uint16 length + data
    const sigLen = (data[offset] << 8) | data[offset + 1];
    offset += 2;
    const signature = data.subarray(offset, offset + sigLen);
    offset += sigLen;

    scts.push({ version, logID, timestamp: ts, extensions, hashAlgorithm, signatureAlgorithm, signature });
  }

  return scts;
}

/**
 * Remove an extension from a TBS certificate by OID bytes.
 * Returns a new TBS with the extension removed and lengths re-encoded.
 */
export function removeTbsExtension(tbs: Uint8Array, targetOid: Uint8Array): Uint8Array {
  const tbsOuter = readTL(tbs, 0);
  if (tbsOuter.tag !== 0x30) throw new Error("DER: TBS is not a SEQUENCE");

  // Find the extensions wrapper (0xA3)
  let offset = tbsOuter.headerSize;
  const parts: Uint8Array[] = [];

  while (offset < tbs.length) {
    const tl = readTL(tbs, offset);
    const elementEnd = offset + tl.headerSize + tl.length;

    if (tl.tag === 0xa3) {
      // Rebuild extensions without the target OID
      const extData = tbs.subarray(offset + tl.headerSize, elementEnd);
      const newExtSeq = removeExtensionFromSequence(extData, targetOid);
      // Re-wrap in 0xA3 context tag
      const wrapped = wrapTag(0xa3, newExtSeq);
      parts.push(tbs.subarray(tbsOuter.headerSize, offset));
      parts.push(wrapped);
      // Any remaining data after extensions
      if (elementEnd < tbs.length) {
        parts.push(tbs.subarray(elementEnd));
      }
      // Wrap in outer SEQUENCE
      const innerLen = parts.reduce((sum, p) => sum + p.length, 0);
      const inner = new Uint8Array(innerLen);
      let pos = 0;
      for (const p of parts) {
        inner.set(p, pos);
        pos += p.length;
      }
      return wrapTag(0x30, inner);
    }

    offset = elementEnd;
  }

  // No extensions found, return as-is
  return tbs;
}

function removeExtensionFromSequence(data: Uint8Array, targetOid: Uint8Array): Uint8Array {
  const outer = readTL(data, 0);
  if (outer.tag !== 0x30) throw new Error("DER: extensions wrapper is not a SEQUENCE");

  const extParts: Uint8Array[] = [];
  let offset = outer.headerSize;
  const end = outer.headerSize + outer.length;

  while (offset < end) {
    const extSeqTL = readTL(data, offset);
    const extEnd = offset + extSeqTL.headerSize + extSeqTL.length;
    const pos = offset + extSeqTL.headerSize;

    // Read OID
    const oidTL = readTL(data, pos);
    const oid = data.subarray(pos + oidTL.headerSize, pos + oidTL.headerSize + oidTL.length);

    // Skip if this is the target OID
    if (!bytesEqual(oid, targetOid)) {
      extParts.push(data.subarray(offset, extEnd));
    }

    offset = extEnd;
  }

  // Reassemble SEQUENCE
  const totalLen = extParts.reduce((sum, p) => sum + p.length, 0);
  const result = new Uint8Array(totalLen);
  let pos = 0;
  for (const p of extParts) {
    result.set(p, pos);
    pos += p.length;
  }
  return wrapTag(0x30, result);
}

/** Wrap content bytes with a DER tag and length */
function wrapTag(tag: number, content: Uint8Array): Uint8Array {
  const lenBytes = encodeDerLength(content.length);
  const result = new Uint8Array(1 + lenBytes.length + content.length);
  result[0] = tag;
  result.set(lenBytes, 1);
  result.set(content, 1 + lenBytes.length);
  return result;
}

function encodeDerLength(length: number): Uint8Array {
  if (length < 0x80) {
    return new Uint8Array([length]);
  } else if (length < 0x100) {
    return new Uint8Array([0x81, length]);
  } else if (length < 0x10000) {
    return new Uint8Array([0x82, (length >> 8) & 0xff, length & 0xff]);
  } else {
    return new Uint8Array([0x83, (length >> 16) & 0xff, (length >> 8) & 0xff, length & 0xff]);
  }
}

export function parseAsn1Time(bytes: Uint8Array, tag: number): Date {
  const str = new TextDecoder().decode(bytes);
  let date: Date;
  if (tag === 0x17) {
    // UTCTime: YYMMDDHHMMSSZ — strict format validation
    if (!/^\d{12}Z$/.test(str)) {
      throw new Error(`DER: malformed UTCTime: "${str}"`);
    }
    const yy = parseInt(str.slice(0, 2), 10);
    const year = yy >= 50 ? 1900 + yy : 2000 + yy;
    date = new Date(
      Date.UTC(
        year,
        parseInt(str.slice(2, 4), 10) - 1,
        parseInt(str.slice(4, 6), 10),
        parseInt(str.slice(6, 8), 10),
        parseInt(str.slice(8, 10), 10),
        parseInt(str.slice(10, 12), 10),
      ),
    );
  } else if (tag === 0x18) {
    // GeneralizedTime: YYYYMMDDHHMMSSZ — strict format validation
    if (!/^\d{14}Z$/.test(str)) {
      throw new Error(`DER: malformed GeneralizedTime: "${str}"`);
    }
    date = new Date(
      Date.UTC(
        parseInt(str.slice(0, 4), 10),
        parseInt(str.slice(4, 6), 10) - 1,
        parseInt(str.slice(6, 8), 10),
        parseInt(str.slice(8, 10), 10),
        parseInt(str.slice(10, 12), 10),
        parseInt(str.slice(12, 14), 10),
      ),
    );
  } else {
    throw new Error(`DER: unknown time tag 0x${tag.toString(16)}`);
  }
  if (Number.isNaN(date.getTime())) {
    throw new Error(`DER: invalid date from ASN.1 time: "${str}"`);
  }
  return date;
}
