import type { SevReport } from "../types.ts";

const REPORT_SIZE = 0x4a0; // 1184 bytes
const SIGNATURE_OFFSET = 0x2a0; // 672 bytes

const ZEN3ZEN4_FAMILY = 0x19;
const ZEN5_FAMILY = 0x1a;
const MILAN_MODEL = 0x01;
const GENOA_MODEL = 0x11;
const TURIN_MODEL = 0x02;

/** Parse a raw SEV-SNP attestation report (1184 bytes) */
export function parseSevReport(data: Uint8Array): SevReport {
  if (data.length < REPORT_SIZE) {
    throw new Error(`SEV-SNP report too short: ${data.length} bytes, need at least ${REPORT_SIZE}`);
  }

  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);

  const version = view.getUint32(0x00, true);
  const guestSvn = view.getUint32(0x04, true);
  const policy = view.getBigUint64(0x08, true);

  // Validate policy reserved bit 17 must be 1
  if (!(policy & (1n << 17n))) {
    throw new Error("SEV-SNP: policy reserved bit 17 must be 1");
  }

  // Validate policy bits 63-26 must be zero
  if (policy >> 26n) {
    throw new Error("SEV-SNP: policy bits 63-26 must be zero");
  }

  const familyId = data.subarray(0x10, 0x20);
  const imageId = data.subarray(0x20, 0x30);
  const vmpl = view.getUint32(0x30, true);
  const signatureAlgo = view.getUint32(0x34, true);

  if (signatureAlgo !== 1) {
    throw new Error(`SEV-SNP: unsupported signature algorithm ${signatureAlgo}, expected 1 (ECDSA P-384 SHA-384)`);
  }

  const currentTcb = view.getBigUint64(0x38, true);
  const platformInfo = view.getBigUint64(0x40, true);
  const signerInfo = view.getUint32(0x48, true);

  // Validate signer is VCEK (bits [4:2] = 0)
  const signingKey = (signerInfo >> 2) & 0x07;
  if (signingKey !== 0) {
    throw new Error(`SEV-SNP: unsupported signing key type ${signingKey}, expected 0 (VCEK)`);
  }

  const reportData = data.subarray(0x50, 0x90);
  const measurement = data.subarray(0x90, 0xc0);
  const hostData = data.subarray(0xc0, 0xe0);
  const idKeyDigest = data.subarray(0xe0, 0x110);
  const authorKeyDigest = data.subarray(0x110, 0x140);
  const reportId = data.subarray(0x140, 0x160);
  const reportIdMa = data.subarray(0x160, 0x180);
  const reportedTcb = view.getBigUint64(0x180, true);

  // Product identification
  let family: number;
  let model: number;
  let productName: string;

  if (version >= 3) {
    family = data[0x188];
    model = data[0x189];
    // stepping = data[0x18a];
    productName = getProductName(family, model);
  } else if (version === 2) {
    family = ZEN3ZEN4_FAMILY;
    model = GENOA_MODEL;
    productName = "Genoa";
  } else {
    throw new Error(`SEV-SNP: unsupported report version ${version}`);
  }

  const chipId = data.subarray(0x1a0, 0x1e0);
  const committedTcb = view.getBigUint64(0x1e0, true);
  const currentBuild = data[0x1e8];
  const currentMinor = data[0x1e9];
  const currentMajor = data[0x1ea];
  const committedBuild = data[0x1ec];
  const committedMinor = data[0x1ed];
  const committedMajor = data[0x1ee];
  const launchTcb = view.getBigUint64(0x1f0, true);

  const signedData = data.subarray(0, SIGNATURE_OFFSET);
  const signature = data.subarray(SIGNATURE_OFFSET, REPORT_SIZE);

  // Debug = policy bit 19
  const debug = !!(policy & (1n << 19n));

  return {
    version,
    guestSvn,
    policy,
    familyId,
    imageId,
    vmpl,
    signatureAlgo,
    currentTcb,
    platformInfo,
    signerInfo,
    reportData,
    measurement,
    hostData,
    idKeyDigest,
    authorKeyDigest,
    reportId,
    reportIdMa,
    reportedTcb,
    chipId,
    committedTcb,
    currentBuild,
    currentMinor,
    currentMajor,
    committedBuild,
    committedMinor,
    committedMajor,
    launchTcb,
    signedData,
    signature,
    debug,
    productName,
  };
}

function getProductName(family: number, model: number): string {
  if (family === ZEN3ZEN4_FAMILY) {
    if (model === MILAN_MODEL) return "Milan";
    if (model === GENOA_MODEL) return "Genoa";
  } else if (family === ZEN5_FAMILY) {
    if (model === TURIN_MODEL) return "Turin";
  }
  return "Unknown";
}
