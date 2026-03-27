/** Trusted root containing Fulcio CAs, Rekor keys, CT log keys, and TSA certs. */
export interface TrustedRoot {
  certificateAuthorities: CertificateAuthority[];
  tlogs: TransparencyLogInstance[];
  ctlogs: TransparencyLogInstance[];
  timestampAuthorities: CertificateAuthority[];
}

export interface CertificateAuthority {
  subject: { organization: string; commonName: string };
  uri: string;
  validFor: { start: string; end?: string };
  certChain: {
    certificates: Array<{ rawBytes: string }>; // base64 DER
  };
}

export interface TransparencyLogInstance {
  baseUrl: string;
  hashAlgorithm: string;
  publicKey: {
    rawBytes: string; // base64 SPKI or raw key
    keyDetails: string; // "PKIX_ECDSA_P256_SHA_256" or "PKIX_ED25519"
    validFor: { start: string; end?: string };
  };
  logId: { keyId: string }; // base64
}

/** Fulcio certificate identity extracted from X.509 extensions. */
export interface FulcioIdentity {
  oidcIssuer: string;
  sourceRepoUri: string;
  sourceRepoRef: string;
  sourceRepoDigest: string;
  buildSignerUri: string;
}

/** Fulcio OID definitions (1.3.6.1.4.1.57264.1.x)
 *  See: https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md
 *  v1 (.1-.6) use raw bytes, v2 (.8+) use proper UTF8String encoding. */
export const FULCIO_OIDS = {
  issuer: "1.3.6.1.4.1.57264.1.1", // OIDC Issuer (v1, raw bytes)
  issuerV2: "1.3.6.1.4.1.57264.1.8", // OIDC Issuer (v2, UTF8String)
  buildSignerUri: "1.3.6.1.4.1.57264.1.9", // Build Signer URI (workflow file URL)
  buildSignerDigest: "1.3.6.1.4.1.57264.1.10", // Build Signer Digest
  runnerEnv: "1.3.6.1.4.1.57264.1.11", // Runner Environment
  sourceRepoUri: "1.3.6.1.4.1.57264.1.12", // Source Repository URI
  sourceRepoDigest: "1.3.6.1.4.1.57264.1.13", // Source Repository Digest
  sourceRepoRef: "1.3.6.1.4.1.57264.1.14", // Source Repository Ref
  buildConfigUri: "1.3.6.1.4.1.57264.1.18", // Build Config URI (top-level build instructions)
  buildConfigDigest: "1.3.6.1.4.1.57264.1.19", // Build Config Digest
  buildTrigger: "1.3.6.1.4.1.57264.1.20", // Build Trigger (e.g. "push")
  runInvocationUri: "1.3.6.1.4.1.57264.1.21", // Run Invocation URI
} as const;

/** SCT extension OID (Certificate Transparency) */
export const EXTENSION_OID_SCT = "1.3.6.1.4.1.11129.2.4.2";

/** Parsed Sigstore bundle */
export interface ParsedBundle {
  mediaType: string;
  signingCert: Uint8Array;
  envelope: {
    payload: Uint8Array;
    payloadType: string;
    signature: Uint8Array;
  };
  tlogEntry: TLogEntryData;
  tlogEntries: TLogEntryData[];
  rfc3161Timestamps: Uint8Array[];
}

/** Parsed transparency log entry */
export interface TLogEntryData {
  logIndex: bigint;
  logId: Uint8Array;
  integratedTime: number;
  canonicalizedBody: Uint8Array;
  kindVersion: { kind: string; version: string };
  inclusionPromise?: {
    signedEntryTimestamp: Uint8Array;
  };
  inclusionProof?: {
    logIndex: bigint;
    rootHash: Uint8Array;
    treeSize: bigint;
    hashes: Uint8Array[];
    checkpoint: string;
  };
}

/** Signed Certificate Timestamp (from CT extension) */
export interface SignedCertificateTimestamp {
  version: number;
  logID: Uint8Array; // 32 bytes — SHA-256 of CT log public key
  timestamp: bigint; // milliseconds since epoch
  extensions: Uint8Array;
  hashAlgorithm: number; // 4 = SHA-256
  signatureAlgorithm: number; // 3 = ECDSA
  signature: Uint8Array; // DER-encoded ECDSA signature
}

/** Log checkpoint parsed from a Rekor checkpoint envelope */
export interface LogCheckpoint {
  origin: string;
  logSize: bigint;
  logHash: Uint8Array;
}

/** Sigstore verification options */
export interface SigstoreVerifyOptions {
  expectedDigest: string;
  expectedRepo: string;
  oidcIssuer?: string;
  workflowRefPattern?: RegExp;
  tlogThreshold?: number;
  ctlogThreshold?: number;
  timestampThreshold?: number;
  /** Fetch live trusted root from Sigstore instead of using baked-in data.
   *  Requires network access. Will not work in browsers (no CORS). */
  liveTrustedRoot?: boolean;
  /** Override Sigstore trusted root URL (default: sigstore/root-signing GitHub raw). */
  trustedRootUrl?: string;
  /** Expected predicate type URL. If set, rejects bundles with a different predicateType. */
  expectedPredicateType?: string;
}

/** Code measurements from Sigstore predicate */
export interface CodeMeasurements {
  snpMeasurement?: string;
  tdxRtmr1?: string;
  tdxRtmr2?: string;
}

/** Sigstore verification result */
export interface SigstoreVerifyResult {
  valid: boolean;
  error?: string;
  errorCode?: SigstoreErrorCode;
  predicateType: string;
  measurements: CodeMeasurements;
  oidcIssuer: string;
  workflowRef: string;
  sourceRepo: string;
  logIndex: number;
  integratedTime: number;
}

/** Provenance verification result */
export interface ProvenanceVerifyResult extends SigstoreVerifyResult {
  measurementMatch: boolean;
  platform: "tdx" | "sev-snp";
}

/** Sigstore error codes */
export type SigstoreErrorCode =
  | "BUNDLE_PARSE_ERROR"
  | "CERTIFICATE_ERROR"
  | "SIGNATURE_ERROR"
  | "TLOG_ERROR"
  | "TLOG_INCLUSION_PROOF_ERROR"
  | "TLOG_INCLUSION_PROMISE_ERROR"
  | "TLOG_BODY_ERROR"
  | "TIMESTAMP_ERROR"
  | "POLICY_ERROR"
  | "PAYLOAD_ERROR"
  | "PROVENANCE_ERROR";

export class SigstoreError extends Error {
  code: SigstoreErrorCode;
  constructor(code: SigstoreErrorCode, message: string) {
    super(message);
    this.code = code;
    this.name = "SigstoreError";
  }
}
