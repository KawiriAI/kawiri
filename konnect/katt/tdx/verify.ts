import { checkCertRevoked, parsePemChain, verifyCertSignature, verifyCrlSignature } from "../cert.ts";
import { extractSpki, extractValidity, hasKeyCertSignUsage, isCaCert, parseCertificate } from "../der.ts";
import type { TdxVerifyOptions, TdxVerifyResult } from "../types.ts";
import { constantTimeEqual, toHex } from "../util.ts";
import { INTEL_ROOT_CA_DER } from "./certs.ts";
import bakedCollateral from "./collateral.generated.ts";
import type { CollateralData } from "./collateral.ts";
import {
  fetchLiveCollateral,
  matchQeIdentity,
  matchTcbLevel,
  mergeTcbStatus,
  tcbStatusAcceptable,
  verifyCollateralSignature,
} from "./collateral.ts";
import { extractPckExtensions } from "./fmspc.ts";
import { parseTdxQuote } from "./parse.ts";

export { parseTdxQuote } from "./parse.ts";

/**
 * Verify a raw TDX attestation quote.
 *
 * Performs the full verification chain:
 * 1. Parse quote structure
 * 2. Verify quote body signature (ECDSA P-256 over header+body)
 * 3. Verify QE report hash (attestation key bound to QE report)
 * 4. Parse PEM certificate chain
 * 5. Verify certificate chain, CRLs (PCK + Root CA), and TCB level
 * 6. Verify QE report signature + QE identity enforcement + TCB merge
 * 7. Extract measurements and apply policy checks (attributes, MRSEAM)
 */
export async function verifyTdxQuote(quoteBytes: Uint8Array, opts?: TdxVerifyOptions): Promise<TdxVerifyResult> {
  const result: TdxVerifyResult = {
    valid: false,
    mrtd: "",
    rtmr0: "",
    rtmr1: "",
    rtmr2: "",
    rtmr3: "",
    reportData: "",
    debug: false,
    tdAttributes: "",
    xfam: "",
  };

  try {
    // Step 1: Parse quote
    const quote = parseTdxQuote(quoteBytes);

    // Step 1a: Validate header semantic fields
    if (quote.header.attestationKeyType !== 2) {
      result.error = `Step 1: Unsupported attestation key type ${quote.header.attestationKeyType} (expected 2 = ECDSA-P256)`;
      return result;
    }
    if (quote.header.teeType !== 0x81) {
      result.error = `Step 1: Unsupported TEE type 0x${quote.header.teeType.toString(16)} (expected 0x81 = TDX)`;
      return result;
    }

    // Extract measurements early so they're available even on failure
    result.mrtd = toHex(quote.body.mrtd);
    result.rtmr0 = toHex(quote.body.rtmr0);
    result.rtmr1 = toHex(quote.body.rtmr1);
    result.rtmr2 = toHex(quote.body.rtmr2);
    result.rtmr3 = toHex(quote.body.rtmr3);
    result.reportData = toHex(quote.body.reportdata);
    result.tdAttributes = toHex(quote.body.tdattributes);
    result.xfam = toHex(quote.body.xfam);
    result.debug = (quote.body.tdattributes[0] & 0x01) !== 0;
    result.mrseam = toHex(quote.body.mrseam);
    result.mrsignerseam = toHex(quote.body.mrsignerseam);
    result.septVeDisable = (quote.body.tdattributes[3] & 0x10) !== 0;

    // Step 2: Verify quote body signature
    // Import attestation key (prepend 0x04 for uncompressed point)
    const akWithPrefix = new Uint8Array(65);
    akWithPrefix[0] = 0x04;
    akWithPrefix.set(quote.attestationKey, 1);

    const attestationKey = await crypto.subtle.importKey(
      "raw",
      akWithPrefix,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );

    const bodySignatureValid = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      attestationKey,
      quote.signature,
      quote.signedBytes,
    );

    if (!bodySignatureValid) {
      result.error = "Step 2: Quote body signature verification failed";
      return result;
    }

    // Step 3: Verify QE report hash
    // SHA-256(attestation_key || qe_auth_data) should match qe_report[320:352]
    const hashInput = new Uint8Array(quote.attestationKey.length + quote.qeReportCertData.qeAuthData.length);
    hashInput.set(quote.attestationKey, 0);
    hashInput.set(quote.qeReportCertData.qeAuthData, quote.attestationKey.length);

    const expectedHash = await crypto.subtle.digest("SHA-256", hashInput);
    const expectedHashBytes = new Uint8Array(expectedHash);
    const actualHash = quote.qeReportCertData.qeReport.subarray(320, 352);

    if (!constantTimeEqual(expectedHashBytes, actualHash)) {
      result.error = "Step 3: QE report hash verification failed — attestation key not bound to QE report";
      return result;
    }

    // Step 4: Parse PEM certificate chain
    if (quote.qeReportCertData.innerCertDataType !== 5) {
      result.error = `Step 4: Expected inner cert data type 5 (PEM chain), got ${quote.qeReportCertData.innerCertDataType}`;
      return result;
    }

    const pemString = new TextDecoder().decode(quote.qeReportCertData.certChain);
    const certsDer = parsePemChain(pemString);

    // Step 5: Verify certificate chain (all ECDSA P-256)
    // Build full chain: [PCK, Intermediate, ..., Intel Root CA]
    const fullChain = [...certsDer, INTEL_ROOT_CA_DER];

    for (let i = fullChain.length - 1; i >= 0; i--) {
      const child = parseCertificate(fullChain[i]);
      const issuerDer = i === fullChain.length - 1 ? fullChain[i] : fullChain[i + 1];
      const issuer = parseCertificate(issuerDer);
      const issuerSpki = extractSpki(issuer.tbs);

      const valid = await verifyCertSignature(issuerSpki, child.tbs, child.signature, "ecdsa-p256-sha256");

      if (!valid) {
        if (i === fullChain.length - 1) {
          result.error = "Step 5: Intel Root CA self-signature verification failed";
        } else {
          result.error = `Step 5: Certificate chain verification failed at index ${i}`;
        }
        return result;
      }
    }

    // Step 5 (path constraints): Verify CA=true and keyCertSign for non-leaf certs
    for (let i = 1; i < fullChain.length; i++) {
      const cert = parseCertificate(fullChain[i]);
      if (!isCaCert(cert.tbs)) {
        result.error = `Step 5: Certificate at index ${i} is not a CA (missing basicConstraints CA=true)`;
        return result;
      }
      if (!hasKeyCertSignUsage(cert.tbs)) {
        result.error = `Step 5: Certificate at index ${i} lacks keyCertSign in keyUsage`;
        return result;
      }
    }

    // Step 5a: Check certificate validity dates
    if (!opts?.skipDateCheck) {
      const now = new Date();
      const certNames = [
        "PCK",
        ...Array.from({ length: certsDer.length - 1 }, (_, i) => `Intermediate ${i + 1}`),
        "Intel Root CA",
      ];
      for (let i = 0; i < fullChain.length; i++) {
        const cert = parseCertificate(fullChain[i]);
        const validity = extractValidity(cert.tbs);
        if (now < validity.notBefore || now > validity.notAfter) {
          result.error = `Step 5a: ${certNames[i]} certificate not valid (notBefore: ${validity.notBefore.toISOString()}, notAfter: ${validity.notAfter.toISOString()})`;
          return result;
        }
      }
    }

    // Resolve collateral source: live fetch or baked-in
    const pckCert = parseCertificate(fullChain[0]);
    let collateral: CollateralData | null = bakedCollateral;

    if (opts?.liveCollateral) {
      const pckExt = extractPckExtensions(fullChain[0]);
      const fmspcHex = Array.from(pckExt.fmspc)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("")
        .toUpperCase();
      collateral = await fetchLiveCollateral(fmspcHex, opts?.pcsBaseUrl);
    }

    // Require collateral when TCB or CRL checks are enabled
    if (!collateral && (!opts?.skipTcbCheck || !opts?.skipCrlCheck)) {
      result.error =
        "Step 5: Collateral data required for TCB/CRL checks but not available (use skipTcbCheck + skipCrlCheck to bypass)";
      return result;
    }

    // Step 5a2: Verify collateral signatures
    // TCB Info and QE Identity JSON are signed by Intel. The issuer chain provides
    // the signing cert which must chain to Intel Root CA.
    // requireSignedCollateral (default true): fail if chains are missing.
    // Set requireSignedCollateral=false to allow baked collateral without issuer chains.
    const requireSigs = (opts?.requireSignedCollateral ?? true) || opts?.liveCollateral;
    if (collateral?.tcbInfoIssuerChain && collateral.tcbInfoJson) {
      const entry = collateral.entries?.find((e) => e.tcbInfoSignature);
      if (entry?.tcbInfoSignature) {
        await verifyCollateralSignature(collateral.tcbInfoJson, entry.tcbInfoSignature, collateral.tcbInfoIssuerChain);
      } else if (requireSigs) {
        result.error = "Step 5a2: TCB Info signature missing — cannot verify TCB Info";
        return result;
      }
    } else if (requireSigs && !opts?.skipTcbCheck && collateral?.tcbInfoJson) {
      result.error = "Step 5a2: TCB Info issuer chain missing — cannot verify signature";
      return result;
    }
    if (collateral?.qeIdentityIssuerChain && collateral.qeIdentityJson) {
      await verifyCollateralSignature(
        collateral.qeIdentityJson,
        collateral.qeIdentitySignature,
        collateral.qeIdentityIssuerChain,
      );
    } else if (requireSigs && !opts?.skipTcbCheck && collateral?.qeIdentityJson) {
      result.error = "Step 5a2: QE Identity issuer chain missing — cannot verify signature";
      return result;
    }

    // Step 5b: Check PCK CRL (with signature verification)
    // Intel has two PCK CAs (Processor CA and Platform CA). The baked CRL may be
    // from a different CA than the one in the quote's cert chain. We try each
    // verified intermediate as potential CRL issuer. If none match, the CRL is
    // from a different CA and is not applicable to this cert.
    if (!opts?.skipCrlCheck && !collateral?.pckCrlDer) {
      result.error = "Step 5b: CRL check enabled but no PCK CRL available in collateral (use skipCrlCheck to bypass)";
      return result;
    }
    if (!opts?.skipCrlCheck && collateral?.pckCrlDer) {
      let crlVerified = false;
      for (let i = 1; i < fullChain.length; i++) {
        const candidateSpki = extractSpki(parseCertificate(fullChain[i]).tbs);
        try {
          const revoked = await checkCertRevoked(fullChain[0], collateral.pckCrlDer, candidateSpki);
          crlVerified = true;
          if (revoked) {
            result.error = "Step 5b: PCK certificate has been revoked (found in CRL)";
            return result;
          }
          break; // CRL signature verified — no need to try other certs
        } catch {
          // CRL signature didn't match this cert — try next
        }
      }
      // If no cert in the chain could verify the CRL, check if we have a separate
      // CRL issuer chain (from PCS API header) for out-of-chain CRL verification
      if (!crlVerified && collateral.pckCrlIssuerChain) {
        const issuerCerts = parsePemChain(collateral.pckCrlIssuerChain);
        // Verify issuer cert chains to Intel Root CA
        const issuerParsed = parseCertificate(issuerCerts[0]);
        const rootSpki = extractSpki(parseCertificate(INTEL_ROOT_CA_DER).tbs);
        const issuerValid = await verifyCertSignature(
          rootSpki,
          issuerParsed.tbs,
          issuerParsed.signature,
          "ecdsa-p256-sha256",
        );
        if (issuerValid) {
          const issuerSpki = extractSpki(issuerParsed.tbs);
          if (await checkCertRevoked(fullChain[0], collateral.pckCrlDer, issuerSpki)) {
            result.error = "Step 5b: PCK certificate has been revoked (found in CRL)";
            return result;
          }
          crlVerified = true;
        }
      }
      if (!crlVerified) {
        result.error =
          "Step 5b: CRL signature could not be verified — no cert in chain or issuer chain matches CRL issuer";
        return result;
      }
    }

    // Step 5b2: Check Root CA CRL (intermediate cert not revoked by Intel Root CA)
    if (!opts?.skipCrlCheck && collateral?.rootCaCrlDer && fullChain.length >= 3) {
      const rootSpki = extractSpki(parseCertificate(INTEL_ROOT_CA_DER).tbs);
      const rootCrlSigValid = await verifyCrlSignature(rootSpki, collateral.rootCaCrlDer);
      if (!rootCrlSigValid) {
        result.error = "Step 5b2: Root CA CRL signature verification failed";
        return result;
      }
      // Check each intermediate cert (indices 1..n-1, excluding PCK[0] and Root[last])
      for (let i = 1; i < fullChain.length - 1; i++) {
        const revoked = await checkCertRevoked(fullChain[i], collateral.rootCaCrlDer);
        if (revoked) {
          result.error = `Step 5b2: Intermediate certificate at index ${i} has been revoked by Root CA CRL`;
          return result;
        }
      }
    }

    // Step 5c: Check TCB level
    if (!opts?.skipTcbCheck && collateral?.tcbInfoJson) {
      const pckExt = extractPckExtensions(fullChain[0]);
      const tcbMatch = matchTcbLevel(collateral.tcbInfoJson, pckExt, quote.body.teeTcbSvn);
      if (!tcbMatch) {
        result.error = "Step 5c: No matching TCB level found in collateral for this platform";
        return result;
      }

      result.tcbStatus = tcbMatch.status;
      result.advisoryIds = tcbMatch.advisoryIds;
      result.collateralDate = collateral.issueDate;

      // Set collateralStale from TCB Info nextUpdate
      const tcbInfoParsed = JSON.parse(collateral.tcbInfoJson);
      const tcbInfo = tcbInfoParsed.tcbInfo ?? tcbInfoParsed;
      if (tcbInfo.nextUpdate) {
        result.collateralStale = new Date() > new Date(tcbInfo.nextUpdate);
      }

      if (opts?.rejectStaleCollateral && result.collateralStale) {
        result.error = `Step 5c: Collateral is stale (nextUpdate: ${tcbInfo.nextUpdate}) — use liveCollateral or update baked data`;
        return result;
      }

      if (!tcbStatusAcceptable(tcbMatch.status, opts?.minTcbStatus)) {
        result.error = `Step 5c: TCB status '${tcbMatch.status}' does not meet minimum '${opts?.minTcbStatus ?? "non-Revoked"}'`;
        return result;
      }
    }

    // Step 6: Verify QE report signature
    const pckSpki = extractSpki(pckCert.tbs);

    const pckKey = await crypto.subtle.importKey("spki", pckSpki, { name: "ECDSA", namedCurve: "P-256" }, false, [
      "verify",
    ]);

    const qeReportSigValid = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      pckKey,
      quote.qeReportCertData.qeReportSignature,
      quote.qeReportCertData.qeReport,
    );

    if (!qeReportSigValid) {
      result.error = "Step 6: QE report signature verification failed";
      return result;
    }

    // Step 6b: Verify QE identity against QE Identity collateral
    if (!opts?.skipTcbCheck && collateral?.qeIdentityJson) {
      const qeMatch = matchQeIdentity(collateral.qeIdentityJson, quote.qeReportCertData.qeReport);
      if (!qeMatch) {
        result.error =
          "Step 6b: QE report does not match QE Identity collateral (miscselect, attributes, mrsigner, isvprodid, or isvsvn mismatch)";
        return result;
      }
      result.qeTcbStatus = qeMatch.status;
      result.qeAdvisoryIds = qeMatch.advisoryIds;
    }

    // Step 6c: Merge platform TCB status with QE TCB status (take worse)
    if (result.tcbStatus && result.qeTcbStatus) {
      const merged = mergeTcbStatus(result.tcbStatus, result.advisoryIds, result.qeTcbStatus, result.qeAdvisoryIds);
      result.tcbStatus = merged.status;
      result.advisoryIds = merged.advisoryIds;

      // Re-check merged status against minimum
      if (!tcbStatusAcceptable(merged.status, opts?.minTcbStatus)) {
        result.error = `Step 6c: Merged TCB status '${merged.status}' does not meet minimum '${opts?.minTcbStatus ?? "non-Revoked"}'`;
        return result;
      }
    }

    // Step 7: Policy checks
    if (result.debug && !opts?.allowDebug) {
      result.error = "Step 7: TDX debug mode is enabled — TD memory is readable by host";
      return result;
    }

    if (opts?.expectedMrtd) {
      if (!constantTimeEqual(quote.body.mrtd, opts.expectedMrtd)) {
        result.error = `Step 7: MRTD mismatch: got ${result.mrtd}, expected ${toHex(opts.expectedMrtd)}`;
        return result;
      }
    }

    if (opts?.expectedReportData) {
      if (!constantTimeEqual(quote.body.reportdata, opts.expectedReportData)) {
        result.error = `Step 7: Report data mismatch: got ${result.reportData}, expected ${toHex(opts.expectedReportData)}`;
        return result;
      }
    }

    // Step 7b: Validate TD attributes (reserved bits must be zero)
    if (!opts?.skipTdAttributeCheck) {
      const attr = quote.body.tdattributes;
      // Known bits: bit 0 = DEBUG, bit 28 = SEPT_VE_DISABLE
      const knownMask = new Uint8Array(8);
      knownMask[0] = 0x01; // bit 0 (DEBUG)
      knownMask[3] = 0x10; // bit 28 (SEPT_VE_DISABLE) — byte 3, bit 4
      for (let i = 0; i < 8; i++) {
        if (attr[i] & ~knownMask[i]) {
          result.error = `Step 7b: TD attributes byte ${i} has reserved bits set: 0x${attr[i].toString(16).padStart(2, "0")} (mask 0x${knownMask[i].toString(16).padStart(2, "0")})`;
          return result;
        }
      }
    }

    // Step 7c: Optional MRSEAM pinning
    if (opts?.expectedMrseam) {
      if (!constantTimeEqual(quote.body.mrseam, opts.expectedMrseam)) {
        result.error = `Step 7c: MRSEAM mismatch: got ${result.mrseam}, expected ${toHex(opts.expectedMrseam)}`;
        return result;
      }
    }
    if (opts?.expectedMrsignerseam) {
      if (!constantTimeEqual(quote.body.mrsignerseam, opts.expectedMrsignerseam)) {
        result.error = `Step 7c: MRSIGNERSEAM mismatch: got ${result.mrsignerseam}, expected ${toHex(opts.expectedMrsignerseam)}`;
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
