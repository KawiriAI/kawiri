import type { QeReportCertData, TdReportBody, TdxQuote, TdxQuoteHeader } from "../types.ts";

const HEADER_SIZE = 48;
const BODY_SIZE = 584;

/** Parse a raw TDX quote (v4 or v5) into structured fields */
export function parseTdxQuote(quoteBytes: Uint8Array): TdxQuote {
  if (quoteBytes.length < HEADER_SIZE + BODY_SIZE + 4) {
    throw new Error(`Quote too short: ${quoteBytes.length} bytes, need at least ${HEADER_SIZE + BODY_SIZE + 4}`);
  }

  const view = new DataView(quoteBytes.buffer, quoteBytes.byteOffset, quoteBytes.byteLength);

  // --- Header (48 bytes at offset 0) ---
  const header = parseHeader(view, quoteBytes);

  // --- Determine body offset and signed data range ---
  let bodyOffset: number;
  let signedEndOffset: number;

  if (header.version === 4) {
    bodyOffset = HEADER_SIZE; // 48
    signedEndOffset = HEADER_SIZE + BODY_SIZE; // 632
  } else if (header.version === 5) {
    // V5 has a 6-byte body header before the body
    bodyOffset = HEADER_SIZE + 6; // 54
    signedEndOffset = HEADER_SIZE + 6 + BODY_SIZE; // 638
  } else {
    throw new Error(`Unsupported quote version: ${header.version}`);
  }

  if (quoteBytes.length < signedEndOffset + 4) {
    throw new Error(`Quote too short for version ${header.version}: ${quoteBytes.length} bytes`);
  }

  const signedBytes = quoteBytes.subarray(0, signedEndOffset);

  // --- Body (584 bytes) ---
  const body = parseBody(quoteBytes, bodyOffset);

  // --- Signature section ---
  let offset = signedEndOffset;
  const _signatureSectionLength = view.getUint32(offset, true);
  offset += 4;

  // Signature (64 bytes, ECDSA P-256 raw r||s)
  if (quoteBytes.length < offset + 64) {
    throw new Error("Quote truncated: missing signature");
  }
  const signature = quoteBytes.subarray(offset, offset + 64);
  offset += 64;

  // Attestation key (64 bytes, raw X||Y)
  if (quoteBytes.length < offset + 64) {
    throw new Error("Quote truncated: missing attestation key");
  }
  const attestationKey = quoteBytes.subarray(offset, offset + 64);
  offset += 64;

  // Certification data type (2 bytes) + length (4 bytes)
  if (quoteBytes.length < offset + 6) {
    throw new Error("Quote truncated: missing certification data header");
  }
  const certDataType = view.getUint16(offset, true);
  offset += 2;
  const certDataLength = view.getUint32(offset, true);
  offset += 4;

  if (quoteBytes.length < offset + certDataLength) {
    throw new Error("Quote truncated: missing certification data body");
  }

  // Parse certification data type 6 (QeReportCertificationData)
  if (certDataType !== 6) {
    throw new Error(`Unsupported certification data type: ${certDataType}, expected 6`);
  }

  const certDataBody = quoteBytes.subarray(offset, offset + certDataLength);
  const qeReportCertData = parseQeReportCertData(certDataBody);

  return {
    header,
    body,
    signedBytes,
    signature,
    attestationKey,
    certDataType,
    qeReportCertData,
  };
}

function parseHeader(view: DataView, bytes: Uint8Array): TdxQuoteHeader {
  return {
    version: view.getUint16(0, true),
    attestationKeyType: view.getUint16(2, true),
    teeType: view.getUint32(4, true),
    reserved1: bytes.subarray(8, 10),
    reserved2: bytes.subarray(10, 12),
    qeVendorId: bytes.subarray(12, 28),
    userData: bytes.subarray(28, 48),
  };
}

function parseBody(bytes: Uint8Array, offset: number): TdReportBody {
  let pos = offset;
  const slice = (len: number): Uint8Array => {
    const s = bytes.subarray(pos, pos + len);
    pos += len;
    return s;
  };

  return {
    teeTcbSvn: slice(16),
    mrseam: slice(48),
    mrsignerseam: slice(48),
    seamattributes: slice(8),
    tdattributes: slice(8),
    xfam: slice(8),
    mrtd: slice(48),
    mrconfigid: slice(48),
    mrowner: slice(48),
    mrownerconfig: slice(48),
    rtmr0: slice(48),
    rtmr1: slice(48),
    rtmr2: slice(48),
    rtmr3: slice(48),
    reportdata: slice(64),
  };
}

function parseQeReportCertData(data: Uint8Array): QeReportCertData {
  if (data.length < 384 + 64 + 2) {
    throw new Error("QE report certification data too short");
  }

  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let offset = 0;

  // QE report (384 bytes)
  const qeReport = data.subarray(offset, offset + 384);
  offset += 384;

  // QE report signature (64 bytes, ECDSA P-256 raw r||s)
  const qeReportSignature = data.subarray(offset, offset + 64);
  offset += 64;

  // QE auth data
  const qeAuthDataLength = view.getUint16(offset, true);
  offset += 2;

  if (data.length < offset + qeAuthDataLength + 6) {
    throw new Error("QE report certification data truncated at auth data");
  }

  const qeAuthData = data.subarray(offset, offset + qeAuthDataLength);
  offset += qeAuthDataLength;

  // Inner certification data
  const innerCertDataType = view.getUint16(offset, true);
  offset += 2;
  const innerCertDataLength = view.getUint32(offset, true);
  offset += 4;

  if (data.length < offset + innerCertDataLength) {
    throw new Error("QE report certification data truncated at cert chain");
  }

  const certChain = data.subarray(offset, offset + innerCertDataLength);

  return {
    qeReport,
    qeReportSignature,
    qeAuthData,
    innerCertDataType,
    certChain,
  };
}
