// Client

export type {
  CodeMeasurements,
  CollateralData,
  FulcioIdentity,
  PckExtensions,
  ProvenanceVerifyResult,
  QeReportCertData,
  SevCollateralData,
  SevProduct,
  SevReport,
  SevVerifyOptions,
  SevVerifyResult,
  SigstoreErrorCode,
  SigstoreVerifyOptions,
  SigstoreVerifyResult,
  TcbStatus,
  TdReportBody,
  TdxQuote,
  TdxQuoteHeader,
  TdxVerifyOptions,
  TdxVerifyResult,
  TrustedRoot,
} from "@katt/index.ts";
// Katt — attestation verification (embedded submodule)
export {
  fetchLiveCollateral,
  fetchLiveSevCollateral,
  fetchLiveTrustedRoot,
  parseSevReport,
  parseTdxQuote,
  SigstoreError,
  verifyCodeProvenance,
  verifySevReport,
  verifySigstoreBundle,
  verifyTdxQuote,
} from "@katt/index.ts";
export type {
  ExpectedMeasurements,
  KattValidatorOptions,
} from "./attestation/katt_validator.ts";
export { KattValidator } from "./attestation/katt_validator.ts";
// Attestation
export type { AttestationValidator } from "./attestation/validator.ts";
export { StubValidator } from "./attestation/validator.ts";
export type { ConnectTiming, KawiriClientOptions } from "./client.ts";
export { KawiriClient } from "./client.ts";
export type { Keypair } from "./noise/mod.ts";

// Noise (re-export for kawa)
export {
  CipherKey,
  CipherState,
  dh,
  generateKeypair,
  HandshakeState,
  noiseCrypto,
  SymmetricState,
  TransportState,
} from "./noise/mod.ts";
export type { DecodedFrame } from "./transport/framer.ts";
// Framer
export { decode, encode, FrameAssembler } from "./transport/framer.ts";
// Transport types
export type {
  AttestationPayload,
  ChatMessage,
  ChatOptions,
  ChatResult,
  KawiriRequest,
  KawiriResponse,
  KawiriStreamChunk,
} from "./transport/types.ts";
// XWing
export { clientUpgrade, serverUpgrade } from "./xwing/upgrade.ts";
