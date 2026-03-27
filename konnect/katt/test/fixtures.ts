import { readFileSync } from "node:fs";
import { resolve } from "node:path";

if (!import.meta.dirname) throw new Error("expected import.meta.dirname");
const FIXTURES_DIR = resolve(import.meta.dirname, "fixtures");

// --- TDX fixtures ---

// Real TDX Quote v4 from our Granite Rapids machine (Intel Xeon 6527P, FMSPC 70A06D070000)
export const tdxQuote = new Uint8Array(readFileSync(resolve(FIXTURES_DIR, "tdx-quote.bin")));

export const allTdxQuotes = [{ name: "granite_rapids_v4", data: tdxQuote }];

export const hasTdxFixtures = allTdxQuotes.length > 0;

// --- SEV-SNP fixtures (real artifacts from AMD EPYC 9124 Genoa) ---

export const sevAttestationBin = new Uint8Array(readFileSync(resolve(FIXTURES_DIR, "sev-attestation-report.bin")));
export const sevVcekDer = new Uint8Array(readFileSync(resolve(FIXTURES_DIR, "sev-vcek.der")));
export const hasSevFixtures = true;

// --- Intel Root CA ---

export { INTEL_ROOT_CA_DER as intelRootCaDer } from "@katt/tdx/certs.js";

// --- Collateral fixture ---

export interface CollateralFixture {
  pck_crl_issuer_chain: string;
  root_ca_crl: string;
  pck_crl: string;
  tcb_info_issuer_chain: string;
  tcb_info: string;
  tcb_info_signature: string;
  qe_identity_issuer_chain: string;
  qe_identity: string;
  qe_identity_signature: string;
}

export const tdxCollateral: CollateralFixture = JSON.parse(
  readFileSync(resolve(FIXTURES_DIR, "tdx-collateral.json"), "utf-8"),
);

// AMD cert PEM strings for DER tests
export {
  ARK_GENOA_PEM,
  ARK_MILAN_PEM,
  ARK_TURIN_PEM,
  ASK_GENOA_PEM,
  ASK_MILAN_PEM,
  ASK_TURIN_PEM,
} from "@katt/sev/certs.js";
