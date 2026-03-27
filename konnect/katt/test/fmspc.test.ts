import { describe, expect, it } from "bun:test";
import { parsePemChain } from "@katt/cert.js";
import { encodeOid, extractPckExtensions } from "@katt/tdx/fmspc.js";
import { parseTdxQuote } from "@katt/tdx/parse.js";
import { toHex } from "@katt/util.js";
import { allTdxQuotes } from "./fixtures.js";

describe("encodeOid", () => {
  it("encodes simple OID 2.5.29.14", () => {
    // 2.5.29.14 → 0x55 0x1d 0x0e
    const bytes = encodeOid("2.5.29.14");
    expect(bytes).toEqual(new Uint8Array([0x55, 0x1d, 0x0e]));
  });

  it("encodes Intel SGX root OID 1.2.840.113741.1.13.1", () => {
    const bytes = encodeOid("1.2.840.113741.1.13.1");
    // 1.2 → 42 (0x2a)
    // 840 → 0x86, 0x48
    // 113741 → base-128: 113741 = 0x1BC4D → 0x86, 0xF8, 0x4D (actually need to verify)
    expect(bytes[0]).toBe(0x2a); // 1*40 + 2
    expect(bytes.length).toBeGreaterThan(5);
  });

  it("encodes OID with large component 113741", () => {
    // 113741 in base-128: 113741 = 6*128^2 + 124*128 + 77 = 6*16384 + 124*128 + 77
    // Actually: 113741 / 128 = 888 rem 77; 888 / 128 = 6 rem 120
    // So: 0x86 (6|0x80), 0xF8 (120|0x80)... wait let me compute properly
    // 113741 in binary: need to split into 7-bit groups
    // 113741 = 0x1BC4D
    // In 7-bit groups from LSB: 0x4D & 0x7F = 77, (113741>>7)=888, 888&0x7F=120, (888>>7)=6
    // So: [6|0x80, 120|0x80, 77] = [0x86, 0xF8, 0x4D]
    const bytes = encodeOid("1.2.840.113741");
    // Check the 113741 portion: bytes should end with 0x86, 0xf8, 0x4d
    const last3 = bytes.slice(bytes.length - 3);
    expect(last3).toEqual(new Uint8Array([0x86, 0xf8, 0x4d]));
  });
});

describe("extractPckExtensions", () => {
  for (const { name, data } of allTdxQuotes) {
    describe(name, () => {
      it("extracts FMSPC (6 bytes)", () => {
        const quote = parseTdxQuote(data);
        const pemString = new TextDecoder().decode(quote.qeReportCertData.certChain);
        const certs = parsePemChain(pemString);
        const pckExt = extractPckExtensions(certs[0]);
        expect(pckExt.fmspc.length).toBe(6);
        // FMSPC should not be all zeros
        expect(pckExt.fmspc.some((b) => b !== 0)).toBe(true);
      });

      it("extracts CPU_SVN (16 bytes)", () => {
        const quote = parseTdxQuote(data);
        const pemString = new TextDecoder().decode(quote.qeReportCertData.certChain);
        const certs = parsePemChain(pemString);
        const pckExt = extractPckExtensions(certs[0]);
        expect(pckExt.cpuSvn.length).toBe(16);
      });

      it("extracts PCE_SVN as uint16", () => {
        const quote = parseTdxQuote(data);
        const pemString = new TextDecoder().decode(quote.qeReportCertData.certChain);
        const certs = parsePemChain(pemString);
        const pckExt = extractPckExtensions(certs[0]);
        expect(pckExt.pceSvn).toBeGreaterThanOrEqual(0);
        expect(pckExt.pceSvn).toBeLessThan(65536);
      });
    });
  }

  it("granite rapids quote has FMSPC 70A06D070000", () => {
    const quote = parseTdxQuote(allTdxQuotes[0].data);
    const pemString = new TextDecoder().decode(quote.qeReportCertData.certChain);
    const certs = parsePemChain(pemString);
    const pckExt = extractPckExtensions(certs[0]);
    expect(toHex(pckExt.fmspc).toUpperCase()).toBe("70A06D070000");
  });
});
