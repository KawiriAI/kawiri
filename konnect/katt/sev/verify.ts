import { checkCertRevoked, parsePemChain, verifyCertSignature } from "../cert.ts";
import { extractSpki, extractValidity, hasKeyCertSignUsage, isCaCert, parseCertificate } from "../der.ts";
import type { SevVerifyOptions, SevVerifyResult } from "../types.ts";
import { bigIntToBytes, bytesToBigInt, constantTimeEqual, reverseBytes, toHex } from "../util.ts";
import { detectProductFromVcek, getCertsForProduct } from "./certs.ts";
import bakedCollateral from "./collateral.generated.ts";
import type { SevCollateralData } from "./collateral.ts";
import { fetchLiveSevCollateral, parseCrlDates } from "./collateral.ts";
import { parseSevReport } from "./parse.ts";

export { parseSevReport } from "./parse.ts";

/**
 * Verify a raw SEV-SNP attestation report.
 *
 * Performs the full 4-step verification chain:
 * 1. Parse report structure
 * 2. Verify AMD certificate chain (ARK -> ASK -> VCEK, all RSA-PSS SHA-384)
 * 3. Verify report signature (ECDSA P-384 with VCEK public key)
 * 4. Extract measurements and apply policy checks
 */
export async function verifySevReport(
  reportBytes: Uint8Array,
  vcekDer: Uint8Array,
  opts?: SevVerifyOptions,
): Promise<SevVerifyResult> {
  const result: SevVerifyResult = {
    valid: false,
    measurement: "",
    reportData: "",
    hostData: "",
    chipId: "",
    debug: false,
    policy: "",
    version: 0,
    guestSvn: 0,
    productName: "",
  };

  try {
    // Step 1: Parse report
    const report = parseSevReport(reportBytes);

    // Detect product from VCEK cert (more reliable than report for v2)
    const product = detectProductFromVcek(vcekDer);

    // Extract measurements early so they're available even on failure
    result.measurement = toHex(report.measurement);
    result.reportData = toHex(report.reportData);
    result.hostData = toHex(report.hostData);
    result.chipId = toHex(report.chipId);
    result.debug = report.debug;
    result.policy = report.policy.toString(16);
    result.version = report.version;
    result.guestSvn = report.guestSvn;
    result.productName = product;

    // Step 2: Verify AMD certificate chain (all RSA-PSS SHA-384)
    const { arkPem, askPem } = getCertsForProduct(product);
    const arkDer = parsePemChain(arkPem)[0];
    const askDer = parsePemChain(askPem)[0];

    const ark = parseCertificate(arkDer);
    const arkSpki = extractSpki(ark.tbs);

    // Check cert validity if not skipped
    if (!opts?.skipDateCheck) {
      const now = new Date();
      const certs = [
        { name: "ARK", der: arkDer },
        { name: "ASK", der: askDer },
        { name: "VCEK", der: vcekDer },
      ];
      for (const { name, der } of certs) {
        const cert = parseCertificate(der);
        const validity = extractValidity(cert.tbs);
        if (now < validity.notBefore || now > validity.notAfter) {
          result.error = `Step 2: ${name} certificate not valid (notBefore: ${validity.notBefore.toISOString()}, notAfter: ${validity.notAfter.toISOString()})`;
          return result;
        }
      }
    }

    // Verify ARK and ASK are CAs with keyCertSign
    if (!isCaCert(ark.tbs) || !hasKeyCertSignUsage(ark.tbs)) {
      result.error = "Step 2: ARK certificate is not a CA or lacks keyCertSign";
      return result;
    }

    // ARK self-signed
    const arkSelfValid = await verifyCertSignature(arkSpki, ark.tbs, ark.signature, "rsa-pss-sha384");
    if (!arkSelfValid) {
      result.error = "Step 2: ARK self-signature verification failed";
      return result;
    }

    // ARK signs ASK
    const ask = parseCertificate(askDer);
    if (!isCaCert(ask.tbs) || !hasKeyCertSignUsage(ask.tbs)) {
      result.error = "Step 2: ASK certificate is not a CA or lacks keyCertSign";
      return result;
    }
    const askValid = await verifyCertSignature(arkSpki, ask.tbs, ask.signature, "rsa-pss-sha384");
    if (!askValid) {
      result.error = "Step 2: ASK signature verification failed (not signed by ARK)";
      return result;
    }

    // ASK signs VCEK
    const askSpki = extractSpki(ask.tbs);
    const vcek = parseCertificate(vcekDer);
    const vcekValid = await verifyCertSignature(askSpki, vcek.tbs, vcek.signature, "rsa-pss-sha384");
    if (!vcekValid) {
      result.error = "Step 2: VCEK signature verification failed (not signed by ASK)";
      return result;
    }

    // Step 2b: Check VCEK and ASK CRL
    if (!opts?.skipCrlCheck) {
      let collateral: SevCollateralData | null = bakedCollateral;
      if (opts?.liveCollateral) {
        collateral = await fetchLiveSevCollateral(product, opts?.kdsBaseUrl);
      }
      const crlDer = collateral?.crls[product];
      if (!crlDer) {
        result.error = `Step 2b: CRL check enabled but no CRL available for ${product} (use skipCrlCheck to bypass)`;
        return result;
      }

      // Set staleness metadata
      const crlMeta = parseCrlDates(crlDer);
      result.collateralDate = crlMeta.thisUpdate.toISOString();
      result.collateralStale = new Date() > crlMeta.nextUpdate;

      if (opts?.rejectStaleCollateral && result.collateralStale) {
        result.error = `Step 2b: CRL is stale (nextUpdate: ${crlMeta.nextUpdate.toISOString()}) — use liveCollateral or update baked data`;
        return result;
      }

      // Check VCEK revocation (with CRL signature verification)
      if (await checkCertRevoked(vcekDer, crlDer, arkSpki)) {
        result.error = "Step 2b: VCEK certificate has been revoked (found in CRL)";
        return result;
      }

      // Also check ASK is not revoked
      if (await checkCertRevoked(askDer, crlDer)) {
        result.error = "Step 2b: ASK certificate has been revoked (found in CRL)";
        return result;
      }
    }

    // Step 3: Verify report signature (ECDSA P-384)
    const vcekSpki = extractSpki(vcek.tbs);
    const vcekKey = await crypto.subtle.importKey("spki", vcekSpki, { name: "ECDSA", namedCurve: "P-384" }, false, [
      "verify",
    ]);

    // Convert AMD little-endian signature to WebCrypto raw R||S format
    const rawSig = convertAmdSignature(report.signature);

    const reportSigValid = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-384" },
      vcekKey,
      rawSig,
      report.signedData,
    );

    if (!reportSigValid) {
      result.error = "Step 3: Report signature verification failed";
      return result;
    }

    // Step 4: Policy checks
    if (result.debug && !opts?.allowDebug) {
      result.error = "Step 4: SEV-SNP debug mode is enabled — guest memory is readable by host";
      return result;
    }

    if (opts?.expectedMeasurement) {
      if (!constantTimeEqual(report.measurement, opts.expectedMeasurement)) {
        result.error = `Step 4: Measurement mismatch: got ${result.measurement}, expected ${toHex(opts.expectedMeasurement)}`;
        return result;
      }
    }

    if (opts?.expectedReportData) {
      if (!constantTimeEqual(report.reportData, opts.expectedReportData)) {
        result.error = `Step 4: Report data mismatch: got ${result.reportData}, expected ${toHex(opts.expectedReportData)}`;
        return result;
      }
    }

    result.valid = true;
    return result;
  } catch (err) {
    result.error = err instanceof Error ? err.message : String(err);
    return result;
  }
}

/**
 * Convert AMD's little-endian 512-byte signature to WebCrypto's 96-byte raw R||S.
 *
 * AMD stores ECDSA P-384 signatures as:
 *   [0:72]   R (little-endian, zero-padded to 72 bytes)
 *   [72:144] S (little-endian, zero-padded to 72 bytes)
 *   [144:512] zeros
 */
function convertAmdSignature(signature: Uint8Array): Uint8Array {
  // Extract R and S (72 bytes each, AMD little-endian)
  const rLE = signature.subarray(0, 72);
  const sLE = signature.subarray(72, 144);

  // Reverse: little-endian -> big-endian
  const rBE = reverseBytes(rLE);
  const sBE = reverseBytes(sLE);

  // Normalize through BigInt (strips leading zeros from reversal)
  const r = bytesToBigInt(rBE);
  const s = bytesToBigInt(sBE);

  // Fixed 48-byte arrays (P-384 curve size)
  const rRaw = bigIntToBytes(r, 48);
  const sRaw = bigIntToBytes(s, 48);

  // Concatenate: R || S = 96 bytes
  const rawSignature = new Uint8Array(96);
  rawSignature.set(rRaw, 0);
  rawSignature.set(sRaw, 48);

  return rawSignature;
}
