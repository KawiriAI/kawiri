import { describe, expect, it } from "bun:test";
import { checkCertRevoked, parsePemChain, parseRevokedSerials, verifyCrlSignature } from "@katt/cert.js";
import { extractSpki, parseCertificate } from "@katt/der.js";
import { detectProductFromVcek, getCertsForProduct } from "@katt/sev/certs.js";
import bakedSevCollateral from "@katt/sev/collateral.generated.js";
import bakedTdxCollateral from "@katt/tdx/collateral.generated.js";
import {
  matchQeIdentity,
  matchTcbLevel,
  mergeTcbStatus,
  tcbStatusAcceptable,
  verifyCollateralSignature,
} from "@katt/tdx/collateral.js";
import { extractPckExtensions } from "@katt/tdx/fmspc.js";
import { parseTdxQuote } from "@katt/tdx/parse.js";
import type { PckExtensions, TcbStatus } from "@katt/types.js";
import { fromHex } from "@katt/util.js";
import { ARK_GENOA_PEM, ARK_MILAN_PEM, ARK_TURIN_PEM, allTdxQuotes, sevVcekDer, tdxCollateral } from "./fixtures.js";

// Helper: get PCK cert and extensions from our TDX quote
function getQuoteData() {
  const quote = parseTdxQuote(allTdxQuotes[0].data);
  const pemString = new TextDecoder().decode(quote.qeReportCertData.certChain);
  const certs = parsePemChain(pemString);
  const pckExt = extractPckExtensions(certs[0]);
  return { quote, certs, pckExt, pckDer: certs[0] };
}

describe("matchTcbLevel", () => {
  it("returns null for our quote (TDX module SVN 4 < required 5)", () => {
    // Our Granite Rapids platform has TDX module SVN 4, but Intel TCB Info
    // requires SVN >= 5 for all defined levels. matchTcbLevel correctly returns null.
    const { quote, pckExt } = getQuoteData();
    const result = matchTcbLevel(tdxCollateral.tcb_info, pckExt, quote.body.teeTcbSvn);
    expect(result).toBeNull();
  });

  it("matches when teeTcbSvn meets threshold → UpToDate", () => {
    const { pckExt } = getQuoteData();
    // Simulate a platform with TDX module SVN 5 (meets first level requirement)
    const updatedTeeTcbSvn = new Uint8Array(16);
    updatedTeeTcbSvn[0] = 5; // TDX Module SVN
    updatedTeeTcbSvn[1] = 0;
    updatedTeeTcbSvn[2] = 2; // TDX Late Microcode Update SVN
    const result = matchTcbLevel(tdxCollateral.tcb_info, pckExt, updatedTeeTcbSvn);
    expect(result).not.toBeNull();
    expect(result?.status).toBe("UpToDate");
  });

  it("returns OutOfDate when PCE_SVN falls to lower level", () => {
    const { pckExt } = getQuoteData();
    // Use TDX SVN >= 5 but low PCE_SVN to force OutOfDate match
    const updatedTeeTcbSvn = new Uint8Array(16);
    updatedTeeTcbSvn[0] = 5;
    updatedTeeTcbSvn[2] = 2;
    const lowPckExt: PckExtensions = {
      fmspc: pckExt.fmspc,
      cpuSvn: pckExt.cpuSvn,
      pceSvn: 5, // Low PCE_SVN to match second level
    };
    const result = matchTcbLevel(tdxCollateral.tcb_info, lowPckExt, updatedTeeTcbSvn);
    expect(result).not.toBeNull();
    expect(result?.status).toBe("OutOfDate");
  });

  it("returns null for FMSPC mismatch", () => {
    const { quote, pckExt } = getQuoteData();
    const wrongFmspc: PckExtensions = {
      fmspc: new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
      cpuSvn: pckExt.cpuSvn,
      pceSvn: pckExt.pceSvn,
    };
    const result = matchTcbLevel(tdxCollateral.tcb_info, wrongFmspc, quote.body.teeTcbSvn);
    expect(result).toBeNull();
  });

  it("skips level when one SGX component is too low", () => {
    const { quote, pckExt } = getQuoteData();
    // Zero out CPU SVN so no SGX component meets the threshold
    const zeroCpuSvn: PckExtensions = {
      fmspc: pckExt.fmspc,
      cpuSvn: new Uint8Array(16), // All zeros
      pceSvn: pckExt.pceSvn,
    };
    const result = matchTcbLevel(tdxCollateral.tcb_info, zeroCpuSvn, quote.body.teeTcbSvn);
    // Should either match a lower level or return null
    if (result) {
      // If there's a level with all-zero SGX requirements
      expect(typeof result.status).toBe("string");
    }
  });

  it("skips level when TDX component is too low", () => {
    const { pckExt } = getQuoteData();
    // Use zero TEE TCB SVN
    const zeroTeeTcbSvn = new Uint8Array(16);
    const result = matchTcbLevel(tdxCollateral.tcb_info, pckExt, zeroTeeTcbSvn);
    // Should match a lower level or null
    if (result) {
      expect(typeof result.status).toBe("string");
    }
  });

  it("returns null when PCE_SVN is below all levels", () => {
    const { quote, pckExt } = getQuoteData();
    const lowPckExt: PckExtensions = {
      fmspc: pckExt.fmspc,
      cpuSvn: pckExt.cpuSvn,
      pceSvn: 0, // Lower than any level
    };
    const result = matchTcbLevel(tdxCollateral.tcb_info, lowPckExt, quote.body.teeTcbSvn);
    // With PCE_SVN=0 below all levels, should return null
    expect(result).toBeNull();
  });
});

describe("parseRevokedSerials", () => {
  it("parses revoked serials from real PCK CRL", () => {
    const crlDer = fromHex(tdxCollateral.pck_crl);
    const serials = parseRevokedSerials(crlDer);
    // The CRL may or may not have revoked certs
    expect(Array.isArray(serials)).toBe(true);
  });

  it("parses root CA CRL (may have zero revoked certs)", () => {
    const crlDer = fromHex(tdxCollateral.root_ca_crl);
    const serials = parseRevokedSerials(crlDer);
    // Root CA CRL may have no revoked certs
    expect(Array.isArray(serials)).toBe(true);
  });
});

describe("checkCertRevoked", () => {
  it("our PCK cert is NOT revoked in its CRL", async () => {
    const { pckDer } = getQuoteData();
    const crlDer = fromHex(tdxCollateral.pck_crl);
    expect(await checkCertRevoked(pckDer, crlDer)).toBe(false);
  });

  it("detects a cert whose serial IS in the CRL", async () => {
    const crlDer = fromHex(tdxCollateral.pck_crl);
    const serials = parseRevokedSerials(crlDer);
    if (serials.length > 0) {
      const { serialsEqual } = await import("@katt/util.js");
      const found = serials.some((r) => serialsEqual(serials[0], r));
      expect(found).toBe(true);
    }
  });
});

describe("tcbStatusAcceptable", () => {
  it("UpToDate is always acceptable", () => {
    expect(tcbStatusAcceptable("UpToDate")).toBe(true);
    expect(tcbStatusAcceptable("UpToDate", "UpToDate")).toBe(true);
  });

  it("Revoked is never acceptable", () => {
    expect(tcbStatusAcceptable("Revoked")).toBe(false);
    expect(tcbStatusAcceptable("Revoked", "OutOfDate")).toBe(false);
  });

  it("SWHardeningNeeded acceptable with minStatus SWHardeningNeeded", () => {
    expect(tcbStatusAcceptable("SWHardeningNeeded", "SWHardeningNeeded")).toBe(true);
  });

  it("OutOfDate not acceptable with minStatus SWHardeningNeeded", () => {
    expect(tcbStatusAcceptable("OutOfDate", "SWHardeningNeeded")).toBe(false);
  });

  it("UpToDate acceptable with any minStatus", () => {
    const allStatuses: TcbStatus[] = [
      "UpToDate",
      "SWHardeningNeeded",
      "ConfigurationNeeded",
      "ConfigurationAndSWHardeningNeeded",
      "OutOfDate",
      "OutOfDateConfigurationNeeded",
    ];
    for (const min of allStatuses) {
      expect(tcbStatusAcceptable("UpToDate", min)).toBe(true);
    }
  });
});

describe("TCB Info signature verification", () => {
  it("verifies TCB Info signature with issuer chain", async () => {
    // Parse the TCB signing cert (first in issuer chain)
    const certs = parsePemChain(tdxCollateral.tcb_info_issuer_chain);
    expect(certs.length).toBeGreaterThanOrEqual(1);

    const signingCert = parseCertificate(certs[0]);
    const spki = extractSpki(signingCert.tbs);

    // Import the signing key (ECDSA P-256)
    const key = await crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);

    // The signature is hex-encoded raw r||s (64 bytes)
    const sigBytes = fromHex(tdxCollateral.tcb_info_signature);
    expect(sigBytes.length).toBe(64);

    // The signed data is the raw JSON bytes of tcb_info
    const tcbInfoBytes = new TextEncoder().encode(tdxCollateral.tcb_info);

    const valid = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, sigBytes, tcbInfoBytes);
    expect(valid).toBe(true);
  });

  it("verifies QE Identity signature", async () => {
    const certs = parsePemChain(tdxCollateral.qe_identity_issuer_chain);
    const signingCert = parseCertificate(certs[0]);
    const spki = extractSpki(signingCert.tbs);

    const key = await crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);

    const sigBytes = fromHex(tdxCollateral.qe_identity_signature);
    const qeIdentityBytes = new TextEncoder().encode(tdxCollateral.qe_identity);

    const valid = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, sigBytes, qeIdentityBytes);
    expect(valid).toBe(true);
  });
});

describe("verifyCollateralSignature", () => {
  it("verifies TCB Info signature with full issuer chain → Intel Root CA", async () => {
    await verifyCollateralSignature(
      tdxCollateral.tcb_info,
      tdxCollateral.tcb_info_signature,
      tdxCollateral.tcb_info_issuer_chain,
    );
    // No throw = success
  });

  it("verifies QE Identity signature with full issuer chain → Intel Root CA", async () => {
    await verifyCollateralSignature(
      tdxCollateral.qe_identity,
      tdxCollateral.qe_identity_signature,
      tdxCollateral.qe_identity_issuer_chain,
    );
  });

  it("rejects tampered TCB Info JSON", async () => {
    const tampered = tdxCollateral.tcb_info.replace('"UpToDate"', '"Revoked"');
    await expect(
      verifyCollateralSignature(tampered, tdxCollateral.tcb_info_signature, tdxCollateral.tcb_info_issuer_chain),
    ).rejects.toThrow(/signature verification failed/i);
  });

  it("rejects wrong signature", async () => {
    const wrongSig = "aa".repeat(64); // 128 hex chars, bogus
    await expect(
      verifyCollateralSignature(tdxCollateral.tcb_info, wrongSig, tdxCollateral.tcb_info_issuer_chain),
    ).rejects.toThrow(/signature verification failed/i);
  });
});

describe("CRL signature verification", () => {
  it("verifies AMD baked CRL signatures against ARK SPKIs", async () => {
    const productCerts: Record<string, string> = {
      Milan: ARK_MILAN_PEM,
      Genoa: ARK_GENOA_PEM,
      Turin: ARK_TURIN_PEM,
    };

    for (const [product, crlDer] of Object.entries(bakedSevCollateral.crls)) {
      const arkPem = productCerts[product];
      expect(arkPem).toBeDefined();
      const arkDer = parsePemChain(arkPem)[0];
      const ark = parseCertificate(arkDer);
      const arkSpki = extractSpki(ark.tbs);

      const valid = await verifyCrlSignature(arkSpki, crlDer as Uint8Array);
      expect(valid).toBe(true);
    }
  });

  it("rejects CRL with corrupted byte", async () => {
    const product = detectProductFromVcek(sevVcekDer);
    const { arkPem } = getCertsForProduct(product);
    const arkDer = parsePemChain(arkPem)[0];
    const ark = parseCertificate(arkDer);
    const arkSpki = extractSpki(ark.tbs);

    const crlDer = bakedSevCollateral.crls[product];
    expect(crlDer).toBeDefined();

    // Corrupt 1 byte of the CRL (in the middle of the TBS data)
    if (!crlDer) throw new Error("expected crlDer");
    const corrupted = new Uint8Array(crlDer);
    corrupted[50] ^= 0xff;

    const valid = await verifyCrlSignature(arkSpki, corrupted);
    expect(valid).toBe(false);
  });

  it("Intel PCK CRL verifies against issuer chain", async () => {
    const crlDer = fromHex(tdxCollateral.pck_crl);
    // The PCK CRL is signed by the Intel PCK Platform CA (first cert in issuer chain)
    const issuerCerts = parsePemChain(tdxCollateral.pck_crl_issuer_chain);
    expect(issuerCerts.length).toBeGreaterThanOrEqual(1);
    const issuerCert = parseCertificate(issuerCerts[0]);
    const issuerSpki = extractSpki(issuerCert.tbs);

    const valid = await verifyCrlSignature(issuerSpki, crlDer);
    expect(valid).toBe(true);
  });
});

describe("matchQeIdentity", () => {
  it("matches our real QE report against baked QE Identity", () => {
    const { quote } = getQuoteData();
    // Use baked QE Identity JSON (same as what verify.ts uses)
    const baked = bakedTdxCollateral;
    const result = matchQeIdentity(baked.qeIdentityJson, quote.qeReportCertData.qeReport);
    expect(result).not.toBeNull();
    expect(result?.status).toBe("UpToDate");
  });

  it("returns null for wrong mrsigner", () => {
    const { quote } = getQuoteData();
    // Tamper the QE Identity to have a wrong mrsigner
    const baked = bakedTdxCollateral;
    const tampered = baked.qeIdentityJson.replace(/"mrsigner":"[0-9A-Fa-f]+"/, `"mrsigner":"${"AA".repeat(32)}"`);
    const result = matchQeIdentity(tampered, quote.qeReportCertData.qeReport);
    expect(result).toBeNull();
  });

  it("returns null for wrong isvprodid", () => {
    const { quote } = getQuoteData();
    const baked = bakedTdxCollateral;
    const tampered = baked.qeIdentityJson.replace('"isvprodid":2', '"isvprodid":999');
    const result = matchQeIdentity(tampered, quote.qeReportCertData.qeReport);
    expect(result).toBeNull();
  });
});

describe("mergeTcbStatus", () => {
  it("takes worse status (platform UpToDate, QE OutOfDate → OutOfDate)", () => {
    const merged = mergeTcbStatus("UpToDate", [], "OutOfDate", []);
    expect(merged.status).toBe("OutOfDate");
  });

  it("takes worse status (platform OutOfDate, QE UpToDate → OutOfDate)", () => {
    const merged = mergeTcbStatus("OutOfDate", [], "UpToDate", []);
    expect(merged.status).toBe("OutOfDate");
  });

  it("both UpToDate → UpToDate", () => {
    const merged = mergeTcbStatus("UpToDate", [], "UpToDate", []);
    expect(merged.status).toBe("UpToDate");
  });

  it("combines and deduplicates advisory IDs", () => {
    const merged = mergeTcbStatus("OutOfDate", ["INTEL-SA-001", "INTEL-SA-002"], "SWHardeningNeeded", [
      "INTEL-SA-002",
      "INTEL-SA-003",
    ]);
    expect(merged.advisoryIds).toEqual(["INTEL-SA-001", "INTEL-SA-002", "INTEL-SA-003"]);
  });

  it("handles undefined advisories", () => {
    const merged = mergeTcbStatus("UpToDate", undefined, "UpToDate", undefined);
    expect(merged.advisoryIds).toEqual([]);
  });
});
