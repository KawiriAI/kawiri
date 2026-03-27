// ===== Intel TDX =====

/** TCB status levels, from most secure to least */
export type TcbStatus =
  | "UpToDate"
  | "SWHardeningNeeded"
  | "ConfigurationNeeded"
  | "ConfigurationAndSWHardeningNeeded"
  | "OutOfDate"
  | "OutOfDateConfigurationNeeded"
  | "Revoked";

/** Options for TDX quote verification */
export interface TdxVerifyOptions {
  /** Expected MRTD value (48 bytes). Rejects if it doesn't match. */
  expectedMrtd?: Uint8Array;
  /** Expected report data (64 bytes). Rejects if it doesn't match. */
  expectedReportData?: Uint8Array;
  /** Allow debug-mode quotes. Default false. */
  allowDebug?: boolean;
  /** Skip TCB level checking even when collateral is available. */
  skipTcbCheck?: boolean;
  /** Skip CRL revocation checking even when collateral is available. */
  skipCrlCheck?: boolean;
  /** Skip certificate date validation. Default false. Use for test certs. */
  skipDateCheck?: boolean;
  /** Minimum acceptable TCB status. Default: accept any non-Revoked. */
  minTcbStatus?: TcbStatus;
  /** Fetch live collateral from Intel PCS API instead of using baked-in data.
   *  Requires network access. Will not work in browsers (no CORS). */
  liveCollateral?: boolean;
  /** Override Intel PCS API base URL (default: https://api.trustedservices.intel.com). */
  pcsBaseUrl?: string;
  /** Require cryptographic signature verification on all collateral (TCB Info, QE Identity)
   *  regardless of source (baked or live). Fails if issuer chains or signatures are missing.
   *  Default true — protects against supply-chain compromise of baked collateral.
   *  Set to false only if using collateral without issuer chains. */
  requireSignedCollateral?: boolean;
  /** Reject verification if collateral has passed its nextUpdate date.
   *  Default false — stale collateral is reported via `collateralStale` but not rejected.
   *  Set to true for production deployments that require fresh revocation/TCB data. */
  rejectStaleCollateral?: boolean;
  /** Skip TD attributes validation (reserved bits, SEPT_VE_DISABLE). Default false. */
  skipTdAttributeCheck?: boolean;
  /** Expected MRSEAM value (48 bytes). If set, rejects if MRSEAM doesn't match. */
  expectedMrseam?: Uint8Array;
  /** Expected MRSIGNERSEAM value (48 bytes). If set, rejects if MRSIGNERSEAM doesn't match. */
  expectedMrsignerseam?: Uint8Array;
}

/** Result of TDX quote verification */
export interface TdxVerifyResult {
  /** Whether the quote passed all verification steps */
  valid: boolean;
  /** Error message if verification failed */
  error?: string;
  /** Build-time measurement (96 hex chars = 48 bytes SHA-384) */
  mrtd: string;
  /** Runtime measurement register 0 (96 hex chars) */
  rtmr0: string;
  /** Runtime measurement register 1 (96 hex chars) */
  rtmr1: string;
  /** Runtime measurement register 2 (96 hex chars) */
  rtmr2: string;
  /** Runtime measurement register 3 (96 hex chars) */
  rtmr3: string;
  /** User-defined report data (128 hex chars = 64 bytes) */
  reportData: string;
  /** Whether the TD is in debug mode */
  debug: boolean;
  /** TD attributes as hex string */
  tdAttributes: string;
  /** Extended Feature Access Mask as hex string */
  xfam: string;
  /** TCB status from collateral checking (undefined if collateral unavailable) */
  tcbStatus?: TcbStatus;
  /** Advisory IDs from TCB matching (undefined if collateral unavailable) */
  advisoryIds?: string[];
  /** Issue date of the TCB Info collateral */
  collateralDate?: string;
  /** Whether the collateral has passed its nextUpdate date */
  collateralStale?: boolean;
  /** MRSEAM measurement (96 hex chars = 48 bytes SHA-384) */
  mrseam?: string;
  /** MRSIGNERSEAM measurement (96 hex chars = 48 bytes SHA-384) */
  mrsignerseam?: string;
  /** Whether SEPT_VE_DISABLE is set in TD attributes (bit 28) */
  septVeDisable?: boolean;
  /** QE TCB status from QE Identity matching */
  qeTcbStatus?: TcbStatus;
  /** Advisory IDs from QE Identity matching */
  qeAdvisoryIds?: string[];
}

/** Parsed TDX quote header */
export interface TdxQuoteHeader {
  /** Quote version (4 or 5) */
  version: number;
  /** Attestation key type (2 = ECDSA-P256) */
  attestationKeyType: number;
  /** TEE type (0x81 = TDX) */
  teeType: number;
  /** Reserved field 1 */
  reserved1: Uint8Array;
  /** Reserved field 2 */
  reserved2: Uint8Array;
  /** QE vendor UUID */
  qeVendorId: Uint8Array;
  /** User data */
  userData: Uint8Array;
}

/** Parsed TD Report Body */
export interface TdReportBody {
  teeTcbSvn: Uint8Array;
  mrseam: Uint8Array;
  mrsignerseam: Uint8Array;
  seamattributes: Uint8Array;
  tdattributes: Uint8Array;
  xfam: Uint8Array;
  mrtd: Uint8Array;
  mrconfigid: Uint8Array;
  mrowner: Uint8Array;
  mrownerconfig: Uint8Array;
  rtmr0: Uint8Array;
  rtmr1: Uint8Array;
  rtmr2: Uint8Array;
  rtmr3: Uint8Array;
  reportdata: Uint8Array;
}

/** QE Report Certification Data (cert data type 6) */
export interface QeReportCertData {
  /** Full 384-byte QE report */
  qeReport: Uint8Array;
  /** ECDSA P-256 signature of qeReport (64 bytes, raw r||s) */
  qeReportSignature: Uint8Array;
  /** QE authentication data */
  qeAuthData: Uint8Array;
  /** Inner certification data type (expect 5 = PEM chain) */
  innerCertDataType: number;
  /** PEM certificate chain bytes */
  certChain: Uint8Array;
}

/** A fully parsed TDX quote */
export interface TdxQuote {
  header: TdxQuoteHeader;
  body: TdReportBody;
  /** Bytes that were signed (header + body) */
  signedBytes: Uint8Array;
  /** ECDSA P-256 signature (64 bytes, raw r||s) */
  signature: Uint8Array;
  /** Attestation public key (64 bytes, raw X||Y without 0x04 prefix) */
  attestationKey: Uint8Array;
  /** Certification data type */
  certDataType: number;
  /** QE report certification data (when certDataType == 6) */
  qeReportCertData: QeReportCertData;
}

// ===== Intel PCK Extensions =====

/** Extensions extracted from an Intel PCK certificate */
export interface PckExtensions {
  /** FMSPC identifier (6 bytes) */
  fmspc: Uint8Array;
  /** CPU SVN components (16 bytes) */
  cpuSvn: Uint8Array;
  /** PCE SVN (uint16) */
  pceSvn: number;
}

// ===== AMD SEV-SNP =====

/** Options for SEV-SNP report verification */
export interface SevVerifyOptions {
  /** Expected launch measurement (48 bytes). Rejects if it doesn't match. */
  expectedMeasurement?: Uint8Array;
  /** Expected report data (64 bytes). Rejects if it doesn't match. */
  expectedReportData?: Uint8Array;
  /** Allow debug-mode reports. Default false. */
  allowDebug?: boolean;
  /** Skip certificate date validation. Default false. Use for test certs. */
  skipDateCheck?: boolean;
  /** Skip CRL revocation checking even when collateral is available. */
  skipCrlCheck?: boolean;
  /** Fetch live CRL from AMD KDS instead of using baked-in data.
   *  Requires network access. Will not work in browsers (no CORS). */
  liveCollateral?: boolean;
  /** Override AMD KDS base URL (default: https://kdsintf.amd.com/vcek/v1). */
  kdsBaseUrl?: string;
  /** Reject verification if CRL collateral has passed its nextUpdate date.
   *  Default false — stale collateral is reported via `collateralStale` but not rejected.
   *  Set to true for production deployments that require fresh revocation data. */
  rejectStaleCollateral?: boolean;
}

/** Result of SEV-SNP report verification */
export interface SevVerifyResult {
  /** Whether the report passed all verification steps */
  valid: boolean;
  /** Error message if verification failed */
  error?: string;
  /** Launch measurement (96 hex chars = 48 bytes) */
  measurement: string;
  /** User-defined report data (128 hex chars = 64 bytes) */
  reportData: string;
  /** Host-provided data (64 hex chars = 32 bytes) */
  hostData: string;
  /** Unique chip identifier (128 hex chars = 64 bytes) */
  chipId: string;
  /** Whether the guest is in debug mode */
  debug: boolean;
  /** Guest policy as hex string */
  policy: string;
  /** Report version */
  version: number;
  /** Guest security version number */
  guestSvn: number;
  /** Processor product name */
  productName: string;
  /** CRL thisUpdate date (ISO 8601) */
  collateralDate?: string;
  /** Whether the CRL has passed its nextUpdate date */
  collateralStale?: boolean;
}

/** A fully parsed SEV-SNP attestation report */
export interface SevReport {
  version: number;
  guestSvn: number;
  policy: bigint;
  familyId: Uint8Array;
  imageId: Uint8Array;
  vmpl: number;
  signatureAlgo: number;
  currentTcb: bigint;
  platformInfo: bigint;
  signerInfo: number;
  reportData: Uint8Array;
  measurement: Uint8Array;
  hostData: Uint8Array;
  idKeyDigest: Uint8Array;
  authorKeyDigest: Uint8Array;
  reportId: Uint8Array;
  reportIdMa: Uint8Array;
  reportedTcb: bigint;
  chipId: Uint8Array;
  committedTcb: bigint;
  currentBuild: number;
  currentMinor: number;
  currentMajor: number;
  committedBuild: number;
  committedMinor: number;
  committedMajor: number;
  launchTcb: bigint;
  signedData: Uint8Array;
  signature: Uint8Array;
  debug: boolean;
  productName: string;
}
