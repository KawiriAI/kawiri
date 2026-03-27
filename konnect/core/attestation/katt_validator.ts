import type { SevVerifyOptions, SevVerifyResult, TdxVerifyOptions, TdxVerifyResult } from "@katt/index.ts";
import { fetchVcek, parseSevReport, verifySevReport, verifyTdxQuote } from "@katt/index.ts";
import type { AttestationPayload } from "../transport/types.ts";
import type { AttestationValidator } from "./validator.ts";

/** Expected measurements to verify against (from build manifest). */
export interface ExpectedMeasurements {
  /** TDX measurements */
  tdx?: {
    mrtd?: string;
    rtmr0?: string;
    rtmr1?: string;
    rtmr2?: string;
  };
  /** SNP launch digest per CPU type (e.g. { "Milan": "abcd...", "Genoa": "ef01..." }) */
  snp?: Record<string, string>;
}

export interface KattValidatorOptions {
  /** Expected measurements from the build manifest. */
  expectedMeasurements?: ExpectedMeasurements;
  /** Fetch live collateral from Intel PCS / AMD KDS. Default false. */
  liveCollateral?: boolean;
  /** Accept mock attestation payloads (dev only). Default false. */
  allowMock?: boolean;
  /** Allow debug-mode TEE quotes. Default false. */
  allowDebug?: boolean;
  /** Skip TCB level check (accept outdated firmware). Default false. */
  skipTcbCheck?: boolean;
  /** Called with verification result for logging/inspection. */
  onResult?: (result: TdxVerifyResult | SevVerifyResult) => void;
}

/**
 * AttestationValidator that uses katt to verify real TDX/SEV-SNP quotes.
 *
 * During the Noise XX handshake, the server sends an AttestationPayload
 * containing a hardware-generated quote. This validator:
 * 1. Verifies the nonce binds the quote to this specific handshake
 * 2. Verifies the cryptographic chain (cert chain, signature, TCB)
 * 3. Optionally checks measurements against known-good values
 */
export class KattValidator implements AttestationValidator {
  constructor(private opts: KattValidatorOptions = {}) {}

  async validate(payload: AttestationPayload, serverStaticKey: Uint8Array): Promise<boolean> {
    // Mock attestation: only accept if explicitly allowed
    if (payload.platform === "mock") {
      if (this.opts.allowMock === true) {
        console.warn(
          "[kawiri] ⚠ MOCK ATTESTATION — connection is NOT running in a confidential TEE. " +
            "Data is not hardware-protected. Do not use in production.",
        );
        return true;
      }
      return false;
    }

    if (!payload.quote) {
      return false;
    }

    // Verify nonce: must equal SHA-256(serverStaticKey) in hex
    const expectedNonce = await sha256Hex(serverStaticKey);
    if (payload.nonce !== expectedNonce) {
      return false;
    }

    // Decode the quote from base64
    const quoteBytes = base64ToBytes(payload.quote);

    // The nonce (32 bytes) is placed in the first 32 bytes of reportData (64 bytes total)
    const nonceBytes = hexToBytes(expectedNonce);
    const reportData = new Uint8Array(64);
    reportData.set(nonceBytes);

    if (payload.platform === "TDX") {
      return this.verifyTdx(quoteBytes, reportData);
    } else if (payload.platform === "SEV-SNP") {
      return this.verifySev(quoteBytes, reportData, payload.certChain);
    }

    return false;
  }

  private async verifyTdx(quoteBytes: Uint8Array, reportData: Uint8Array): Promise<boolean> {
    const opts: TdxVerifyOptions = {
      expectedReportData: reportData,
      allowDebug: this.opts.allowDebug ?? false,
      liveCollateral: this.opts.liveCollateral ?? false,
      skipTcbCheck: this.opts.skipTcbCheck ?? false,
    };

    const expected = this.opts.expectedMeasurements?.tdx;
    if (expected?.mrtd) {
      opts.expectedMrtd = hexToBytes(expected.mrtd);
    }

    const result = await verifyTdxQuote(quoteBytes, opts);
    this.opts.onResult?.(result);

    if (!result.valid) return false;

    // Additional RTMR checks (katt doesn't have these as built-in options)
    if (expected) {
      if (expected.rtmr0 && result.rtmr0 !== expected.rtmr0) {
        console.error(`[kawiri] RTMR0 mismatch: got ${result.rtmr0}, expected ${expected.rtmr0}`);
        return false;
      }
      if (expected.rtmr1 && result.rtmr1 !== expected.rtmr1) {
        console.error(`[kawiri] RTMR1 mismatch: got ${result.rtmr1}, expected ${expected.rtmr1}`);
        return false;
      }
      if (expected.rtmr2 && result.rtmr2 !== expected.rtmr2) {
        console.error(`[kawiri] RTMR2 mismatch: got ${result.rtmr2}, expected ${expected.rtmr2}`);
        return false;
      }
    }

    return true;
  }

  private async verifySev(reportBytes: Uint8Array, reportData: Uint8Array, certChain?: string): Promise<boolean> {
    // Get VCEK DER: from PEM cert chain if provided, otherwise fetch from AMD KDS
    let vcekDer: Uint8Array | null = null;
    if (certChain) {
      vcekDer = pemToFirstDer(certChain);
    }
    if (!vcekDer) {
      const report = parseSevReport(reportBytes);
      console.warn(`[katt] no cert chain provided, fetching VCEK from AMD KDS for ${report.productName}`);
      vcekDer = await fetchVcek(report.productName as "Milan" | "Genoa" | "Turin", report.chipId, report.reportedTcb);
    }

    const opts: SevVerifyOptions = {
      expectedReportData: reportData,
      allowDebug: this.opts.allowDebug ?? false,
      liveCollateral: this.opts.liveCollateral ?? false,
    };

    const result = await verifySevReport(reportBytes, vcekDer, opts);
    this.opts.onResult?.(result);

    if (!result.valid) return false;

    // Check measurement against expected values (any CPU type match is OK)
    const snpExpected = this.opts.expectedMeasurements?.snp;
    if (snpExpected) {
      const match = Object.values(snpExpected).some((digest) => digest === result.measurement);
      if (!match) return false;
    }

    return true;
  }
}

// --- Helpers ---

async function sha256Hex(data: Uint8Array): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", data);
  return bytesToHex(new Uint8Array(hash));
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

/** Extract the first DER certificate from a PEM chain. */
function pemToFirstDer(pem: string): Uint8Array | null {
  const match = pem.match(/-----BEGIN CERTIFICATE-----\s*([\s\S]*?)\s*-----END CERTIFICATE-----/);
  if (!match) return null;
  return base64ToBytes(match[1].replace(/\s/g, ""));
}
