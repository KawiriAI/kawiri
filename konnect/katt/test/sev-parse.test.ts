import { describe, expect, it } from "bun:test";
import { parseSevReport } from "@katt/sev/parse.js";
import { hasSevFixtures, sevAttestationBin } from "./fixtures.js";

describe("parseSevReport", () => {
  if (!hasSevFixtures || !sevAttestationBin) {
    it("skipped: add local SEV fixtures in test/fixtures/", () => {});
    return;
  }

  it("parses go-sev-guest attestation.bin", () => {
    const report = parseSevReport(sevAttestationBin);
    expect(report).toBeDefined();
  });

  it("has valid version (2, 3, or 5)", () => {
    const report = parseSevReport(sevAttestationBin);
    expect([2, 3, 5]).toContain(report.version);
  });

  it("has signature_algo = 1 (ECDSA P-384 SHA-384)", () => {
    const report = parseSevReport(sevAttestationBin);
    expect(report.signatureAlgo).toBe(1);
  });

  it("has policy bit 17 set", () => {
    const report = parseSevReport(sevAttestationBin);
    expect(report.policy & (1n << 17n)).toBeTruthy();
  });

  it("has 48-byte non-zero measurement", () => {
    const report = parseSevReport(sevAttestationBin);
    expect(report.measurement.length).toBe(48);
    // At least some bytes should be non-zero
    expect(report.measurement.some((b) => b !== 0)).toBe(true);
  });

  it("has 64-byte reportData", () => {
    const report = parseSevReport(sevAttestationBin);
    expect(report.reportData.length).toBe(64);
  });

  it("has 64-byte chipId", () => {
    const report = parseSevReport(sevAttestationBin);
    expect(report.chipId.length).toBe(64);
  });

  it("has signedData = first 672 bytes", () => {
    const report = parseSevReport(sevAttestationBin);
    expect(report.signedData.length).toBe(672);
    // signedData should match the first 0x2A0 bytes of input
    expect(report.signedData).toEqual(sevAttestationBin.slice(0, 0x2a0));
  });

  it("has 512-byte signature at offset 0x2A0", () => {
    const report = parseSevReport(sevAttestationBin);
    expect(report.signature.length).toBe(512);
    expect(report.signature).toEqual(sevAttestationBin.slice(0x2a0, 0x4a0));
  });

  it("has debug as a boolean", () => {
    const report = parseSevReport(sevAttestationBin);
    expect(typeof report.debug).toBe("boolean");
  });

  it("has a valid product name", () => {
    const report = parseSevReport(sevAttestationBin);
    expect(["Milan", "Genoa", "Turin", "Unknown"]).toContain(report.productName);
  });

  it("throws on truncated input", () => {
    const truncated = new Uint8Array(100);
    expect(() => parseSevReport(truncated)).toThrow();
  });

  it("throws on policy with bit 17 cleared", () => {
    const modified = new Uint8Array(sevAttestationBin);
    // Clear bit 17 in the policy field (at offset 0x08, little-endian u64)
    // Bit 17 is in the third byte (bits 16-23) at offset 0x0A
    modified[0x0a] &= ~0x02; // bit 17 = bit 1 of byte at 0x0A
    expect(() => parseSevReport(modified)).toThrow(/bit 17/i);
  });
});
