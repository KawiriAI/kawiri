import { parsePemChain, verifyCertSignature } from "../cert.ts";
import { extractSpki, hasKeyCertSignUsage, isCaCert, parseCertificate } from "../der.ts";
import type { PckExtensions, TcbStatus } from "../types.ts";
import { fromHex } from "../util.ts";
import { INTEL_ROOT_CA_DER } from "./certs.ts";
import type { CollateralData } from "./collateral.generated.ts";

export type { CollateralData } from "./collateral.generated.ts";

const DEFAULT_PCS_BASE = "https://api.trustedservices.intel.com";

/** Decode a URL-encoded PEM issuer chain header from Intel PCS API. */
function decodeHeaderChain(header: string | null): string | undefined {
  if (!header) return undefined;
  return decodeURIComponent(header);
}

/**
 * Fetch live collateral from Intel PCS API for a given FMSPC.
 * Requires network access — will not work in browsers (no CORS).
 */
export async function fetchLiveCollateral(fmspcHex: string, pcsBaseUrl?: string): Promise<CollateralData> {
  const PCS_BASE = pcsBaseUrl ?? DEFAULT_PCS_BASE;
  const tcbRes = await fetch(`${PCS_BASE}/tdx/certification/v4/tcb?fmspc=${fmspcHex}`);
  if (!tcbRes.ok) throw new Error(`Intel PCS TCB Info: HTTP ${tcbRes.status}`);
  const tcbBody = await tcbRes.text();
  const tcbInfoIssuerChain =
    decodeHeaderChain(tcbRes.headers.get("TCB-Info-Issuer-Chain")) ??
    decodeHeaderChain(tcbRes.headers.get("Sgx-TCB-Info-Issuer-Chain"));

  // Preserve raw JSON bytes — signatures are computed over exact bytes
  const tcbInfoMatch = tcbBody.match(/"tcbInfo"\s*:\s*(\{[\s\S]*\})\s*,\s*"signature"/);
  if (!tcbInfoMatch) throw new Error("Could not extract tcbInfo JSON from PCS response");
  const tcbInfoJson = tcbInfoMatch[1];
  const tcbParsed = JSON.parse(tcbBody);
  const tcbInfo = JSON.parse(tcbInfoJson);

  const qeRes = await fetch(`${PCS_BASE}/tdx/certification/v4/qe/identity`);
  if (!qeRes.ok) throw new Error(`Intel PCS QE Identity: HTTP ${qeRes.status}`);
  const qeBody = await qeRes.text();
  const qeParsed = JSON.parse(qeBody);
  const qeMatch = qeBody.match(/"enclaveIdentity"\s*:\s*(\{[\s\S]*\})\s*,\s*"signature"/);
  const qeIdentityIssuerChain = decodeHeaderChain(qeRes.headers.get("Sgx-Enclave-Identity-Issuer-Chain"));

  const crlRes = await fetch(`${PCS_BASE}/sgx/certification/v4/pckcrl?ca=processor&encoding=der`);
  if (!crlRes.ok) throw new Error(`Intel PCS PCK CRL: HTTP ${crlRes.status}`);
  const pckCrlDer = new Uint8Array(await crlRes.arrayBuffer());
  const pckCrlIssuerChain = decodeHeaderChain(crlRes.headers.get("Sgx-PCK-CRL-Issuer-Chain"));

  // Root CA CRL (for checking intermediate cert revocation)
  let rootCaCrlDer: Uint8Array | undefined;
  try {
    const rootCrlRes = await fetch("https://certificates.trustedservices.intel.com/IntelSGXRootCA.der");
    if (rootCrlRes.ok) {
      rootCaCrlDer = new Uint8Array(await rootCrlRes.arrayBuffer());
    }
  } catch {
    /* Root CA CRL is optional — live fetch may not always have it */
  }

  return {
    entries: [
      {
        fmspc: fmspcHex,
        tcbInfoJson,
        tcbInfoSignature: tcbParsed.signature,
        issueDate: tcbInfo.issueDate,
        nextUpdate: tcbInfo.nextUpdate,
      },
    ],
    tcbInfoJson,
    issueDate: tcbInfo.issueDate,
    qeIdentityJson: qeMatch ? qeMatch[1] : JSON.stringify(qeParsed.enclaveIdentity),
    qeIdentitySignature: qeParsed.signature,
    pckCrlDer,
    rootCaCrlDer,
    pckCrlIssuerChain,
    tcbInfoIssuerChain,
    qeIdentityIssuerChain,
  };
}

/** Result of TCB level matching */
export interface TcbMatchResult {
  status: TcbStatus;
  date: string;
  advisoryIds?: string[];
}

/** Parsed TCB Info structure (from Intel PCS API) */
interface TcbInfo {
  fmspc: string;
  issueDate: string;
  nextUpdate: string;
  tcbLevels: TcbLevel[];
}

interface TcbLevel {
  tcb: {
    sgxtcbcomponents: { svn: number }[];
    tdxtcbcomponents: { svn: number }[];
    pcesvn: number;
  };
  tcbStatus: TcbStatus;
  tcbDate: string;
  advisoryIDs?: string[];
}

/**
 * Match a PCK cert's TCB against the TCB Info levels.
 *
 * Algorithm (from Intel DCAP spec):
 * 1. Verify FMSPC matches
 * 2. Iterate tcbLevels (highest to lowest):
 *    - pce_svn >= level.pcesvn
 *    - cpu_svn component-wise >= level.sgxtcbcomponents[i].svn
 *    - tee_tcb_svn component-wise >= level.tdxtcbcomponents[i].svn
 * 3. Return first match's status + advisoryIDs
 *
 * @param tcbInfoJson Raw JSON string from Intel PCS API (signature verified separately)
 * @param pckExt Extensions extracted from the PCK certificate
 * @param teeTcbSvn 16-byte TEE TCB SVN from the TD report body
 */
export function matchTcbLevel(
  tcbInfoJson: string,
  pckExt: PckExtensions,
  teeTcbSvn: Uint8Array,
): TcbMatchResult | null {
  const parsed = JSON.parse(tcbInfoJson);
  const tcbInfo: TcbInfo = parsed.tcbInfo ?? parsed;

  // Verify FMSPC matches
  const quoteFmspc = Array.from(pckExt.fmspc)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();

  if (tcbInfo.fmspc.toUpperCase() !== quoteFmspc) {
    return null; // FMSPC mismatch — this collateral doesn't apply
  }

  // Iterate TCB levels (ordered highest to lowest by Intel)
  for (const level of tcbInfo.tcbLevels) {
    // Check PCE_SVN
    if (pckExt.pceSvn < level.tcb.pcesvn) {
      continue;
    }

    // Check SGX TCB components (component-wise >=)
    let sgxMatch = true;
    for (let i = 0; i < 16; i++) {
      const required = level.tcb.sgxtcbcomponents[i]?.svn ?? 0;
      const actual = pckExt.cpuSvn[i] ?? 0;
      if (actual < required) {
        sgxMatch = false;
        break;
      }
    }
    if (!sgxMatch) continue;

    // Check TDX TCB components (component-wise >=)
    let tdxMatch = true;
    if (level.tcb.tdxtcbcomponents) {
      for (let i = 0; i < 16; i++) {
        const required = level.tcb.tdxtcbcomponents[i]?.svn ?? 0;
        const actual = teeTcbSvn[i] ?? 0;
        if (actual < required) {
          tdxMatch = false;
          break;
        }
      }
    }
    if (!tdxMatch) continue;

    // Match found
    return {
      status: level.tcbStatus,
      date: level.tcbDate,
      advisoryIds: level.advisoryIDs,
    };
  }

  // No matching level found — likely below all known levels
  return null;
}

/** TCB status severity ordering (lower index = more secure) */
export const TCB_STATUS_ORDER: TcbStatus[] = [
  "UpToDate",
  "SWHardeningNeeded",
  "ConfigurationNeeded",
  "ConfigurationAndSWHardeningNeeded",
  "OutOfDate",
  "OutOfDateConfigurationNeeded",
  "Revoked",
];

/**
 * Check if a TCB status meets the minimum requirement.
 * Returns true if the status is acceptable.
 */
export function tcbStatusAcceptable(status: TcbStatus, minStatus?: TcbStatus): boolean {
  if (status === "Revoked") return false; // Always reject Revoked

  if (!minStatus) return true; // No minimum specified, accept any non-Revoked

  const statusIdx = TCB_STATUS_ORDER.indexOf(status);
  const minIdx = TCB_STATUS_ORDER.indexOf(minStatus);
  // Reject unknown statuses — indexOf returns -1 for unrecognized values
  if (statusIdx === -1 || minIdx === -1) return false;
  return statusIdx <= minIdx;
}

/** Result of QE Identity matching */
export interface QeIdentityMatchResult {
  /** QE TCB status from the matching tcbLevel */
  status: TcbStatus;
  /** Advisory IDs from the matching tcbLevel */
  advisoryIds?: string[];
}

/**
 * Match QE report fields against QE Identity JSON.
 *
 * QE report (384-byte SGX EnclaveReport) field offsets:
 *   miscselect: bytes 16..20 (4 bytes, little-endian)
 *   attributes:  bytes 48..64 (16 bytes)
 *   mrsigner:    bytes 128..160 (32 bytes)
 *   isvprodid:   bytes 256..258 (2 bytes, little-endian)
 *   isvsvn:      bytes 258..260 (2 bytes, little-endian)
 *
 * Matching algorithm:
 *   1. (miscselect & miscselectMask) == (identity.miscselect & miscselectMask)
 *   2. (attributes & attributesMask) == (identity.attributes & attributesMask)
 *   3. mrsigner == identity.mrsigner
 *   4. isvprodid == identity.isvprodid
 *   5. Find highest tcbLevel where isvsvn >= level.tcb.isvsvn
 */
export function matchQeIdentity(qeIdentityJson: string, qeReport: Uint8Array): QeIdentityMatchResult | null {
  const parsed = JSON.parse(qeIdentityJson);
  const identity = parsed.enclaveIdentity ?? parsed;

  // Extract QE report fields
  const qeMiscSelect = qeReport.subarray(16, 20);
  const qeAttributes = qeReport.subarray(48, 64);
  const qeMrSigner = qeReport.subarray(128, 160);
  const qeIsvProdId = qeReport[256] | (qeReport[257] << 8); // LE uint16
  const qeIsvSvn = qeReport[258] | (qeReport[259] << 8); // LE uint16

  // 1. Check miscselect with mask
  const idMiscSelect = fromHex(identity.miscselect);
  const miscMask = fromHex(identity.miscselectMask);
  for (let i = 0; i < 4; i++) {
    if ((qeMiscSelect[i] & miscMask[i]) !== (idMiscSelect[i] & miscMask[i])) {
      return null;
    }
  }

  // 2. Check attributes with mask
  const idAttributes = fromHex(identity.attributes);
  const attrMask = fromHex(identity.attributesMask);
  for (let i = 0; i < 16; i++) {
    if ((qeAttributes[i] & attrMask[i]) !== (idAttributes[i] & attrMask[i])) {
      return null;
    }
  }

  // 3. Check mrsigner
  const idMrSigner = fromHex(identity.mrsigner);
  for (let i = 0; i < 32; i++) {
    if (qeMrSigner[i] !== idMrSigner[i]) return null;
  }

  // 4. Check isvprodid
  if (qeIsvProdId !== identity.isvprodid) return null;

  // 5. Match tcbLevel by isvsvn (levels ordered highest to lowest)
  for (const level of identity.tcbLevels) {
    if (qeIsvSvn >= level.tcb.isvsvn) {
      return {
        status: level.tcbStatus,
        advisoryIds: level.advisoryIDs,
      };
    }
  }

  return null; // Below all known QE TCB levels
}

/**
 * Merge platform TCB status with QE TCB status.
 * Takes the worse (higher index) of the two statuses.
 * Combines advisory IDs from both sources (deduplicated).
 */
export function mergeTcbStatus(
  platformStatus: TcbStatus,
  platformAdvisories: string[] | undefined,
  qeStatus: TcbStatus,
  qeAdvisories: string[] | undefined,
): { status: TcbStatus; advisoryIds: string[] } {
  const pIdx = TCB_STATUS_ORDER.indexOf(platformStatus);
  const qIdx = TCB_STATUS_ORDER.indexOf(qeStatus);
  const status = pIdx >= qIdx ? platformStatus : qeStatus;
  const combined = new Set([...(platformAdvisories ?? []), ...(qeAdvisories ?? [])]);
  return { status, advisoryIds: [...combined].sort() };
}

/**
 * Verify an Intel PCS collateral signature (TCB Info or QE Identity).
 *
 * Intel signs the JSON body with ECDSA P-256 over SHA-256.
 * The signature is 128 hex chars = 64 bytes = raw r||s.
 * The issuer chain PEM contains the signing cert → Intel Root CA.
 *
 * @param jsonString The exact JSON string that was signed (byte-exact)
 * @param signatureHex Hex-encoded raw r||s signature (128 chars)
 * @param issuerChainPem PEM chain: signing cert → ... → Intel Root CA
 * @throws Error if verification fails
 */
export async function verifyCollateralSignature(
  jsonString: string,
  signatureHex: string,
  issuerChainPem: string,
): Promise<void> {
  // Parse issuer chain
  const issuerCerts = parsePemChain(issuerChainPem);
  if (issuerCerts.length === 0) {
    throw new Error("Collateral issuer chain is empty");
  }

  // Verify issuer chain → Intel Root CA
  const _rootSpki = extractSpki(parseCertificate(INTEL_ROOT_CA_DER).tbs);

  // Build full chain: [signing cert, ..., Intel Root CA]
  const fullChain = [...issuerCerts, INTEL_ROOT_CA_DER];
  for (let i = fullChain.length - 1; i >= 0; i--) {
    const child = parseCertificate(fullChain[i]);
    const issuerDer = i === fullChain.length - 1 ? fullChain[i] : fullChain[i + 1];
    const issuer = parseCertificate(issuerDer);

    // Issuer must be a CA with keyCertSign
    if (!isCaCert(issuer.tbs) || !hasKeyCertSignUsage(issuer.tbs)) {
      throw new Error(`Collateral issuer cert is not a CA or lacks keyCertSign`);
    }

    const issuerSpki = extractSpki(issuer.tbs);
    const valid = await verifyCertSignature(issuerSpki, child.tbs, child.signature, "ecdsa-p256-sha256");
    if (!valid) {
      throw new Error(`Collateral issuer chain verification failed at index ${i}`);
    }
  }

  // Extract signing cert's SPKI
  const signingSpki = extractSpki(parseCertificate(issuerCerts[0]).tbs);

  // Import signing key (ECDSA P-256)
  const signingKey = await crypto.subtle.importKey("spki", signingSpki, { name: "ECDSA", namedCurve: "P-256" }, false, [
    "verify",
  ]);

  // Decode hex signature to raw r||s bytes
  const sigBytes = new Uint8Array(signatureHex.length / 2);
  for (let i = 0; i < sigBytes.length; i++) {
    sigBytes[i] = parseInt(signatureHex.substring(i * 2, i * 2 + 2), 16);
  }

  // Verify signature over UTF-8 JSON bytes
  const jsonBytes = new TextEncoder().encode(jsonString);
  const sigValid = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, signingKey, sigBytes, jsonBytes);

  if (!sigValid) {
    throw new Error("Collateral signature verification failed — data may be tampered");
  }
}
