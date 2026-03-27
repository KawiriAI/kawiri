import { describe, expect, it } from "bun:test";
import { checkCertRevoked, parsePemChain, parseRevokedSerials } from "@katt/cert.js";
import { extractSerialNumber, extractSpki, parseCertificate } from "@katt/der.js";
import { detectProductFromVcek, getCertsForProduct } from "@katt/sev/certs.js";
import bakedSevCollateral from "@katt/sev/collateral.generated.js";
import { parseCrlDates } from "@katt/sev/collateral.js";
import { parseSevReport } from "@katt/sev/parse.js";
import { verifySevReport } from "@katt/sev/verify.js";
import { serialsEqual } from "@katt/util.js";
import { hasSevFixtures, sevAttestationBin, sevVcekDer } from "./fixtures.js";

describe("verifySevReport", () => {
  if (!hasSevFixtures || !sevAttestationBin || !sevVcekDer) {
    it("skipped: add local SEV fixtures in test/fixtures/", () => {});
    return;
  }

  it("verifies successfully (valid: true)", async () => {
    const result = await verifySevReport(sevAttestationBin, sevVcekDer, {
      skipDateCheck: true,
    });
    expect(result.valid).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it("returns hex measurements of correct length", async () => {
    const result = await verifySevReport(sevAttestationBin, sevVcekDer, {
      skipDateCheck: true,
    });
    // measurement: 48 bytes = 96 hex chars
    expect(result.measurement).toMatch(/^[0-9a-f]{96}$/);
    // reportData: 64 bytes = 128 hex chars
    expect(result.reportData).toMatch(/^[0-9a-f]{128}$/);
    // chipId: 64 bytes = 128 hex chars
    expect(result.chipId).toMatch(/^[0-9a-f]{128}$/);
    // hostData: 32 bytes = 64 hex chars
    expect(result.hostData).toMatch(/^[0-9a-f]{64}$/);
  });

  it("debug is a boolean", async () => {
    const result = await verifySevReport(sevAttestationBin, sevVcekDer, {
      skipDateCheck: true,
    });
    expect(typeof result.debug).toBe("boolean");
  });

  it("has valid version and product name", async () => {
    const result = await verifySevReport(sevAttestationBin, sevVcekDer, {
      skipDateCheck: true,
    });
    expect(result.version).toBeGreaterThanOrEqual(2);
    expect(["Milan", "Genoa", "Turin", "Unknown"]).toContain(result.productName);
  });

  describe("tamper detection", () => {
    it("rejects corrupted signature (flip byte at 0x2A0)", async () => {
      const corrupted = new Uint8Array(sevAttestationBin);
      corrupted[0x2a0] ^= 0xff;
      const result = await verifySevReport(corrupted, sevVcekDer, {
        skipDateCheck: true,
      });
      expect(result.valid).toBe(false);
    });
  });

  describe("expectedMeasurement", () => {
    it("passes when expectedMeasurement matches", async () => {
      const report = parseSevReport(sevAttestationBin);
      const result = await verifySevReport(sevAttestationBin, sevVcekDer, {
        skipDateCheck: true,
        allowDebug: true,
        expectedMeasurement: report.measurement,
      });
      expect(result.valid).toBe(true);
    });

    it("rejects when expectedMeasurement does not match", async () => {
      const wrongMeasurement = new Uint8Array(48).fill(0xaa);
      const result = await verifySevReport(sevAttestationBin, sevVcekDer, {
        skipDateCheck: true,
        allowDebug: true,
        expectedMeasurement: wrongMeasurement,
      });
      expect(result.valid).toBe(false);
      expect(result.error).toMatch(/measurement/i);
    });
  });

  describe("expectedReportData", () => {
    it("passes when expectedReportData matches", async () => {
      const report = parseSevReport(sevAttestationBin);
      const result = await verifySevReport(sevAttestationBin, sevVcekDer, {
        skipDateCheck: true,
        allowDebug: true,
        expectedReportData: report.reportData,
      });
      expect(result.valid).toBe(true);
    });

    it("rejects when expectedReportData does not match", async () => {
      const wrongData = new Uint8Array(64).fill(0xbb);
      const result = await verifySevReport(sevAttestationBin, sevVcekDer, {
        skipDateCheck: true,
        allowDebug: true,
        expectedReportData: wrongData,
      });
      expect(result.valid).toBe(false);
      expect(result.error).toMatch(/report data/i);
    });
  });

  describe("product detection", () => {
    it("detectProductFromVcek recognizes real VCEK certs", () => {
      // Real VCEK cert from AMD EPYC 9124 has issuer CN "SEV-Genoa"
      expect(detectProductFromVcek(sevVcekDer)).toBe("Genoa");
    });

    it("throws on invalid DER input", () => {
      const unknownCert = new Uint8Array(256);
      expect(() => detectProductFromVcek(unknownCert)).toThrow();
    });
  });

  describe("CRL checking", () => {
    it("VCEK not in baked CRL passes verification", async () => {
      const product = detectProductFromVcek(sevVcekDer);
      const crlDer = bakedSevCollateral.crls[product];
      expect(crlDer).toBeDefined();
      if (!crlDer) throw new Error("expected crlDer");
      expect(await checkCertRevoked(sevVcekDer, crlDer)).toBe(false);
    });

    it("baked CRLs are parseable for all products", () => {
      for (const [_product, crlDer] of Object.entries(bakedSevCollateral.crls)) {
        const serials = parseRevokedSerials(crlDer as Uint8Array);
        expect(Array.isArray(serials)).toBe(true);
      }
    });

    it("verification passes with CRL check enabled (skipCrlCheck=false)", async () => {
      const result = await verifySevReport(sevAttestationBin, sevVcekDer, {
        skipDateCheck: true,
        allowDebug: true,
        skipCrlCheck: false,
      });
      expect(result.valid).toBe(true);
    });

    it("VCEK serial not in baked CRL (explicit check)", () => {
      const product = detectProductFromVcek(sevVcekDer);
      const crlDer = bakedSevCollateral.crls[product];
      if (!crlDer) throw new Error("expected crlDer");
      const revoked = parseRevokedSerials(crlDer);
      const vcek = parseCertificate(sevVcekDer);
      const serial = extractSerialNumber(vcek.tbs);
      const isRevoked = revoked.some((r) => serialsEqual(serial, r));
      expect(isRevoked).toBe(false);
    });

    it("checkCertRevoked verifies CRL signature with ARK SPKI", async () => {
      const product = detectProductFromVcek(sevVcekDer);
      const { arkPem } = getCertsForProduct(product);
      const arkDer = parsePemChain(arkPem)[0];
      const ark = parseCertificate(arkDer);
      const arkSpki = extractSpki(ark.tbs);
      const crlDer = bakedSevCollateral.crls[product];
      expect(crlDer).toBeDefined();
      // Should not throw — CRL signature is valid
      if (!crlDer) throw new Error("expected crlDer");
      expect(await checkCertRevoked(sevVcekDer, crlDer, arkSpki)).toBe(false);
    });

    it("positive revocation: detects VCEK serial injected into revoked list", async () => {
      // Extract the test VCEK serial
      const vcek = parseCertificate(sevVcekDer);
      const vcekSerial = extractSerialNumber(vcek.tbs);

      // Get a real CRL and extract its revoked serials
      const product = detectProductFromVcek(sevVcekDer);
      const crlDer = bakedSevCollateral.crls[product];
      expect(crlDer).toBeDefined();
      if (!crlDer) throw new Error("expected crlDer");
      const revokedSerials = parseRevokedSerials(crlDer);

      // Manually check: if we add our serial to the list, serialsEqual finds it
      const withOurSerial = [...revokedSerials, vcekSerial];
      const found = withOurSerial.some((r) => serialsEqual(vcekSerial, r));
      expect(found).toBe(true);
    });

    it("verifySevReport populates collateralDate and collateralStale", async () => {
      const result = await verifySevReport(sevAttestationBin, sevVcekDer, {
        skipDateCheck: true,
        allowDebug: true,
        skipCrlCheck: false,
      });
      expect(result.valid).toBe(true);
      expect(result.collateralDate).toBeDefined();
      expect(typeof result.collateralDate).toBe("string");
      expect(typeof result.collateralStale).toBe("boolean");
    });

    it("parseCrlDates returns valid dates from baked CRL", () => {
      const product = detectProductFromVcek(sevVcekDer);
      const crlDer = bakedSevCollateral.crls[product];
      expect(crlDer).toBeDefined();
      if (!crlDer) throw new Error("expected crlDer");
      const meta = parseCrlDates(crlDer);
      expect(meta.thisUpdate).toBeInstanceOf(Date);
      expect(meta.nextUpdate).toBeInstanceOf(Date);
      expect(meta.nextUpdate.getTime()).toBeGreaterThan(meta.thisUpdate.getTime());
    });

    it("ASK serial not in baked CRL", () => {
      const product = detectProductFromVcek(sevVcekDer);
      const { askPem } = getCertsForProduct(product);
      const askDer = parsePemChain(askPem)[0];
      const ask = parseCertificate(askDer);
      const askSerial = extractSerialNumber(ask.tbs);
      const crlDer = bakedSevCollateral.crls[product];
      expect(crlDer).toBeDefined();
      if (!crlDer) throw new Error("expected crlDer");
      const revoked = parseRevokedSerials(crlDer);
      const isRevoked = revoked.some((r) => serialsEqual(askSerial, r));
      expect(isRevoked).toBe(false);
    });
  });

  describe("rejectStaleCollateral", () => {
    it("passes by default even when CRL collateral is stale", async () => {
      const result = await verifySevReport(sevAttestationBin, sevVcekDer, {
        skipDateCheck: true,
        allowDebug: true,
        skipCrlCheck: false,
      });
      expect(result.valid).toBe(true);
      expect(typeof result.collateralStale).toBe("boolean");
    });

    it("rejects when rejectStaleCollateral is true and CRL is stale", async () => {
      const result = await verifySevReport(sevAttestationBin, sevVcekDer, {
        skipDateCheck: true,
        allowDebug: true,
        skipCrlCheck: false,
        rejectStaleCollateral: true,
      });
      if (result.collateralStale) {
        expect(result.valid).toBe(false);
        expect(result.error).toMatch(/stale/i);
      } else {
        // If CRL happens to be fresh, it should pass
        expect(result.valid).toBe(true);
      }
    });
  });

  describe("debug mode", () => {
    it("passes when debug=false and allowDebug is false (default)", async () => {
      // The real fixture has debug=false (policy 0x30000, bit 19 not set).
      const result = await verifySevReport(sevAttestationBin, sevVcekDer, {
        skipDateCheck: true,
        allowDebug: false,
      });
      expect(result.debug).toBe(false);
      expect(result.valid).toBe(true);
    });

    it("also passes when allowDebug is true", async () => {
      const result = await verifySevReport(sevAttestationBin, sevVcekDer, {
        skipDateCheck: true,
        allowDebug: true,
      });
      expect(result.valid).toBe(true);
    });

    it("rejects a synthetically debug-enabled report", async () => {
      // Flip bit 19 in the policy to enable debug — signature will be invalid
      const corrupted = new Uint8Array(sevAttestationBin);
      corrupted[0x0a] |= 0x08; // bit 19 = bit 3 of byte at 0x0A
      const result = await verifySevReport(corrupted, sevVcekDer, {
        skipDateCheck: true,
        allowDebug: false,
      });
      // Signature check happens before debug check, so it fails on sig
      expect(result.valid).toBe(false);
    });
  });

  describe("truncated input", () => {
    it("rejects empty report", async () => {
      const result = await verifySevReport(new Uint8Array(0), sevVcekDer, {
        skipDateCheck: true,
      });
      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
    });

    it("rejects report shorter than minimum size", async () => {
      const result = await verifySevReport(new Uint8Array(100), sevVcekDer, {
        skipDateCheck: true,
      });
      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
    });
  });
});
