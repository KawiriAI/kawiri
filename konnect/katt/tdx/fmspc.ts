import { extractExtensions, findExtensionByOid, parseCertificate, readTL } from "../der.ts";
import type { PckExtensions } from "../types.ts";
import { bytesEqual } from "../util.ts";

/**
 * Encode a dotted OID string to DER OID content bytes.
 *
 * First two components are packed: first * 40 + second.
 * Remaining components use base-128 variable-length encoding (high bit = continuation).
 */
export function encodeOid(oidStr: string): Uint8Array {
  const parts = oidStr.split(".").map(Number);
  if (parts.length < 2) {
    throw new Error(`OID too short: ${oidStr}`);
  }

  const bytes: number[] = [];
  // First two components: packed as first * 40 + second
  bytes.push(parts[0] * 40 + parts[1]);

  for (let i = 2; i < parts.length; i++) {
    let value = parts[i];
    if (value < 128) {
      bytes.push(value);
    } else {
      // Base-128 encoding: split into 7-bit groups, high bit set on all but last
      const groups: number[] = [];
      while (value > 0) {
        groups.unshift(value & 0x7f);
        value >>= 7;
      }
      for (let g = 0; g < groups.length; g++) {
        bytes.push(g < groups.length - 1 ? groups[g] | 0x80 : groups[g]);
      }
    }
  }

  return new Uint8Array(bytes);
}

// Intel SGX OIDs
const OID_SGX_EXTENSIONS = encodeOid("1.2.840.113741.1.13.1");
const OID_FMSPC = encodeOid("1.2.840.113741.1.13.1.4");
const OID_TCB = encodeOid("1.2.840.113741.1.13.1.2");
const OID_TCB_COMP_SVN_PREFIX = "1.2.840.113741.1.13.1.2.";
const OID_PCE_SVN = encodeOid("1.2.840.113741.1.13.1.2.17");

/**
 * Extract FMSPC, CPU_SVN, and PCE_SVN from an Intel PCK certificate (DER).
 *
 * PCK certs embed Intel SGX-specific extensions under OID 1.2.840.113741.1.13.1.
 * The SGX extensions container is a nested SEQUENCE of SEQUENCE { OID, value } pairs.
 */
export function extractPckExtensions(certDer: Uint8Array): PckExtensions {
  const cert = parseCertificate(certDer);
  const extensions = extractExtensions(cert.tbs);

  // Find the SGX Extensions container
  const sgxExt = findExtensionByOid(extensions, OID_SGX_EXTENSIONS);
  if (!sgxExt) {
    throw new Error("PCK cert does not contain SGX extensions (OID 1.2.840.113741.1.13.1)");
  }

  // The SGX extension value is a SEQUENCE of SEQUENCE { OID, ANY }
  const sgxItems = parseSgxExtensionSequence(sgxExt.value);

  // Extract FMSPC
  const fmspcEntry = sgxItems.find((e) => bytesEqual(e.oid, OID_FMSPC));
  if (!fmspcEntry) {
    throw new Error("PCK cert missing FMSPC extension");
  }
  const fmspc = extractOctetStringValue(fmspcEntry.value);
  if (fmspc.length !== 6) {
    throw new Error(`FMSPC should be 6 bytes, got ${fmspc.length}`);
  }

  // Extract TCB container → CPU_SVN components + PCE_SVN
  const tcbEntry = sgxItems.find((e) => bytesEqual(e.oid, OID_TCB));
  if (!tcbEntry) {
    throw new Error("PCK cert missing TCB extension");
  }

  const tcbItems = parseSgxExtensionSequence(tcbEntry.value);

  // CPU_SVN: components 1-16 (OIDs 1.2.840.113741.1.13.1.2.1 through .16)
  const cpuSvn = new Uint8Array(16);
  for (let i = 1; i <= 16; i++) {
    const compOid = encodeOid(`${OID_TCB_COMP_SVN_PREFIX}${i}`);
    const comp = tcbItems.find((e) => bytesEqual(e.oid, compOid));
    if (comp) {
      cpuSvn[i - 1] = extractIntegerValue(comp.value);
    }
  }

  // PCE_SVN (OID .17)
  const pceSvnEntry = tcbItems.find((e) => bytesEqual(e.oid, OID_PCE_SVN));
  if (!pceSvnEntry) {
    throw new Error("PCK cert missing PCE_SVN in TCB extension");
  }
  const pceSvn = extractIntegerValue(pceSvnEntry.value);

  return { fmspc, cpuSvn, pceSvn };
}

/** Entry in an SGX extension SEQUENCE */
interface SgxExtEntry {
  oid: Uint8Array;
  value: Uint8Array;
}

/**
 * Parse a SEQUENCE of SEQUENCE { OID, ANY } pairs.
 * This is the format Intel uses for nested SGX extensions.
 */
function parseSgxExtensionSequence(data: Uint8Array): SgxExtEntry[] {
  const outer = readTL(data, 0);
  if (outer.tag !== 0x30) {
    throw new Error(`DER: expected SEQUENCE, got 0x${outer.tag.toString(16)}`);
  }

  const entries: SgxExtEntry[] = [];
  let offset = outer.headerSize;
  const end = outer.headerSize + outer.length;

  while (offset < end) {
    const seqTL = readTL(data, offset);
    if (seqTL.tag !== 0x30) {
      throw new Error(`DER: expected SEQUENCE in SGX ext, got 0x${seqTL.tag.toString(16)}`);
    }
    const seqEnd = offset + seqTL.headerSize + seqTL.length;
    let pos = offset + seqTL.headerSize;

    // OID
    const oidTL = readTL(data, pos);
    if (oidTL.tag !== 0x06) {
      throw new Error("DER: expected OID in SGX extension entry");
    }
    const oid = data.subarray(pos + oidTL.headerSize, pos + oidTL.headerSize + oidTL.length);
    pos += oidTL.headerSize + oidTL.length;

    // Value: remaining bytes in this SEQUENCE (could be OCTET STRING, INTEGER, nested SEQUENCE, etc.)
    const value = data.subarray(pos, seqEnd);

    entries.push({ oid, value });
    offset = seqEnd;
  }

  return entries;
}

/** Extract the raw bytes from an OCTET STRING value */
function extractOctetStringValue(data: Uint8Array): Uint8Array {
  const tl = readTL(data, 0);
  if (tl.tag !== 0x04) {
    throw new Error(`DER: expected OCTET STRING (0x04), got 0x${tl.tag.toString(16)}`);
  }
  return data.subarray(tl.headerSize, tl.headerSize + tl.length);
}

/** Extract an integer value from a DER INTEGER element */
function extractIntegerValue(data: Uint8Array): number {
  const tl = readTL(data, 0);
  if (tl.tag !== 0x02) {
    throw new Error(`DER: expected INTEGER (0x02), got 0x${tl.tag.toString(16)}`);
  }
  let value = 0;
  for (let i = 0; i < tl.length; i++) {
    value = (value << 8) | data[tl.headerSize + i];
  }
  return value;
}
