// ===== Verification =====

// Code provenance (Sigstore + TEE measurement comparison)
export { verifyCodeProvenance } from "./provenance.ts";
// AMD SEV-SNP
export { parseSevReport, verifySevReport } from "./sev/verify.ts";
// Sigstore
export { verifySigstoreBundle } from "./sigstore/verify.ts";
// Intel TDX
export { parseTdxQuote, verifyTdxQuote } from "./tdx/verify.ts";

// ===== Network helpers (optional, require fetch) =====

export { fetchLiveSevCollateral, fetchVcek } from "./sev/collateral.ts";
export { fetchLiveTrustedRoot } from "./sigstore/verify.ts";
export { fetchLiveCollateral } from "./tdx/collateral.ts";

// ===== Error class =====

export { SigstoreError } from "./sigstore/types.ts";

// ===== Types =====

export type { SevProduct } from "./sev/certs.ts";
export type { SevCollateralData } from "./sev/collateral.ts";
export type {
  CodeMeasurements,
  FulcioIdentity,
  ProvenanceVerifyResult,
  SigstoreErrorCode,
  // Sigstore
  SigstoreVerifyOptions,
  SigstoreVerifyResult,
  TrustedRoot,
} from "./sigstore/types.ts";
export type { CollateralData } from "./tdx/collateral.ts";
export type {
  PckExtensions,
  QeReportCertData,
  SevReport,
  // SEV-SNP
  SevVerifyOptions,
  SevVerifyResult,
  TcbStatus,
  TdReportBody,
  TdxQuote,
  TdxQuoteHeader,
  // TDX
  TdxVerifyOptions,
  TdxVerifyResult,
} from "./types.ts";
