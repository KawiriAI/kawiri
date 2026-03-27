import { describe, expect, it } from "bun:test";
import { parseTdxQuote } from "@katt/tdx/parse.js";
import { allTdxQuotes, hasTdxFixtures } from "./fixtures.js";

describe("parseTdxQuote", () => {
  if (!hasTdxFixtures) {
    it("skipped: add local TDX fixtures in test/fixtures/", () => {});
    return;
  }

  for (const { name, data } of allTdxQuotes) {
    describe(name, () => {
      it("parses header correctly", () => {
        const quote = parseTdxQuote(data);
        expect(quote.header.version).toBe(4);
        expect(quote.header.attestationKeyType).toBe(2); // ECDSA-P256
        expect(quote.header.teeType).toBe(0x81); // TDX
      });

      it("parses body field sizes", () => {
        const quote = parseTdxQuote(data);
        expect(quote.body.mrtd.length).toBe(48);
        expect(quote.body.rtmr0.length).toBe(48);
        expect(quote.body.rtmr1.length).toBe(48);
        expect(quote.body.rtmr2.length).toBe(48);
        expect(quote.body.rtmr3.length).toBe(48);
        expect(quote.body.reportdata.length).toBe(64);
        expect(quote.body.tdattributes.length).toBe(8);
        expect(quote.body.xfam.length).toBe(8);
        expect(quote.body.teeTcbSvn.length).toBe(16);
      });

      it("has 64-byte signature and attestation key", () => {
        const quote = parseTdxQuote(data);
        expect(quote.signature.length).toBe(64);
        expect(quote.attestationKey.length).toBe(64);
      });

      it("has certification data type 6", () => {
        const quote = parseTdxQuote(data);
        expect(quote.certDataType).toBe(6);
      });

      it("extracts PEM cert chain with >= 2 certs", () => {
        const quote = parseTdxQuote(data);
        const pemString = new TextDecoder().decode(quote.qeReportCertData.certChain);
        const certCount = (pemString.match(/-----BEGIN CERTIFICATE-----/g) || []).length;
        expect(certCount).toBeGreaterThanOrEqual(2);
      });

      it("has 384-byte QE report", () => {
        const quote = parseTdxQuote(data);
        expect(quote.qeReportCertData.qeReport.length).toBe(384);
      });

      it("has 64-byte QE report signature", () => {
        const quote = parseTdxQuote(data);
        expect(quote.qeReportCertData.qeReportSignature.length).toBe(64);
      });

      it("has inner cert data type 5 (PEM chain)", () => {
        const quote = parseTdxQuote(data);
        expect(quote.qeReportCertData.innerCertDataType).toBe(5);
      });
    });
  }

  it("throws on truncated input", () => {
    const truncated = new Uint8Array(100);
    expect(() => parseTdxQuote(truncated)).toThrow();
  });

  it("throws on wrong version", () => {
    const bad = new Uint8Array(allTdxQuotes[0].data);
    // Set version to 99
    bad[0] = 99;
    bad[1] = 0;
    expect(() => parseTdxQuote(bad)).toThrow(/version/i);
  });
});
