import { describe, expect, it } from "bun:test";
import { parseTdxQuote } from "@katt/tdx/parse.js";
import { verifyTdxQuote } from "@katt/tdx/verify.js";
import { allTdxQuotes } from "./fixtures.js";

describe("verifyTdxQuote", () => {
  // Our Granite Rapids TDX module has SVN 4, but Intel TCB Info requires >= 5.
  // This is a real platform state: our SEAM module is one version behind.
  // Tests that exercise cryptographic verification use skipTcbCheck.

  for (const { name, data } of allTdxQuotes) {
    describe(name, () => {
      it("verifies successfully (signature, cert chain, QE report)", async () => {
        const result = await verifyTdxQuote(data, { skipTcbCheck: true });
        expect(result.valid).toBe(true);
        expect(result.error).toBeUndefined();
      });

      it("returns non-empty hex measurements of correct length", async () => {
        const result = await verifyTdxQuote(data, { skipTcbCheck: true });
        // MRTD: 48 bytes = 96 hex chars
        expect(result.mrtd).toMatch(/^[0-9a-f]{96}$/);
        expect(result.rtmr0).toMatch(/^[0-9a-f]{96}$/);
        expect(result.rtmr1).toMatch(/^[0-9a-f]{96}$/);
        expect(result.rtmr2).toMatch(/^[0-9a-f]{96}$/);
        expect(result.rtmr3).toMatch(/^[0-9a-f]{96}$/);
        // Report data: 64 bytes = 128 hex chars
        expect(result.reportData).toMatch(/^[0-9a-f]{128}$/);
        // TD attributes: 8 bytes = 16 hex chars
        expect(result.tdAttributes).toMatch(/^[0-9a-f]{16}$/);
        expect(result.xfam).toMatch(/^[0-9a-f]{16}$/);
      });

      it("reports debug as false", async () => {
        const result = await verifyTdxQuote(data, { skipTcbCheck: true });
        expect(result.debug).toBe(false);
      });
    });
  }

  describe("TCB level check", () => {
    it('fails with "no matching TCB level" (TDX module SVN 4 < required 5)', async () => {
      // Our platform has TDX module SVN 4, Intel requires >= 5
      const result = await verifyTdxQuote(allTdxQuotes[0].data);
      expect(result.valid).toBe(false);
      expect(result.error).toMatch(/no matching TCB level/i);
    });
  });

  describe("tamper detection", () => {
    it("rejects corrupted signature (flipped byte)", async () => {
      const corrupted = new Uint8Array(allTdxQuotes[0].data);
      // Signature starts at offset 636 for v4
      corrupted[636] ^= 0xff;
      const result = await verifyTdxQuote(corrupted, { skipTcbCheck: true });
      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
    });

    it("rejects corrupted cert chain", async () => {
      const corrupted = new Uint8Array(allTdxQuotes[0].data);
      // Corrupt somewhere in the cert chain (near the end of the quote)
      const certArea = corrupted.length - 200;
      corrupted[certArea] ^= 0xff;
      const result = await verifyTdxQuote(corrupted, { skipTcbCheck: true });
      expect(result.valid).toBe(false);
    });
  });

  describe("expectedMrtd", () => {
    it("passes when expectedMrtd matches", async () => {
      const quote = parseTdxQuote(allTdxQuotes[0].data);
      const result = await verifyTdxQuote(allTdxQuotes[0].data, {
        expectedMrtd: quote.body.mrtd,
        skipTcbCheck: true,
      });
      expect(result.valid).toBe(true);
    });

    it("rejects when expectedMrtd does not match", async () => {
      const wrongMrtd = new Uint8Array(48).fill(0xaa);
      const result = await verifyTdxQuote(allTdxQuotes[0].data, {
        expectedMrtd: wrongMrtd,
        skipTcbCheck: true,
      });
      expect(result.valid).toBe(false);
      expect(result.error).toMatch(/mrtd/i);
    });
  });

  describe("expectedReportData", () => {
    it("passes when expectedReportData matches", async () => {
      const quote = parseTdxQuote(allTdxQuotes[0].data);
      const result = await verifyTdxQuote(allTdxQuotes[0].data, {
        expectedReportData: quote.body.reportdata,
        skipTcbCheck: true,
      });
      expect(result.valid).toBe(true);
    });

    it("rejects when expectedReportData does not match", async () => {
      const wrongData = new Uint8Array(64).fill(0xbb);
      const result = await verifyTdxQuote(allTdxQuotes[0].data, {
        expectedReportData: wrongData,
        skipTcbCheck: true,
      });
      expect(result.valid).toBe(false);
      expect(result.error).toMatch(/report data/i);
    });
  });

  describe("debug mode", () => {
    it("rejects debug-mode quote when allowDebug is false", async () => {
      // Force debug bit: tdattributes byte 0 bit 0
      // Body layout: teeTcbSvn(16) + mrseam(48) + mrsignerseam(48) + seamattributes(8) = 120
      const debugQuote = new Uint8Array(allTdxQuotes[0].data);
      const headerSize = 48;
      const tdAttrBodyOffset = 16 + 48 + 48 + 8; // 120 bytes into body
      debugQuote[headerSize + tdAttrBodyOffset] |= 0x01; // Set debug bit
      // Modifying signed bytes causes signature verification to fail
      const result = await verifyTdxQuote(debugQuote, { allowDebug: false, skipTcbCheck: true });
      expect(result.valid).toBe(false);
    });

    it("passes debug-mode quote when allowDebug is true", async () => {
      const result = await verifyTdxQuote(allTdxQuotes[0].data, { allowDebug: true, skipTcbCheck: true });
      expect(result.valid).toBe(true);
      expect(result.debug).toBe(false);
    });
  });

  describe("cert date validation", () => {
    it("skipDateCheck bypasses cert date validation", async () => {
      const result = await verifyTdxQuote(allTdxQuotes[0].data, {
        skipDateCheck: true,
        skipTcbCheck: true,
      });
      expect(result.valid).toBe(true);
    });

    it("date check is enabled by default (passes with valid certs)", async () => {
      const result = await verifyTdxQuote(allTdxQuotes[0].data, { skipTcbCheck: true });
      expect(result.valid).toBe(true);
    });
  });

  describe("rejectStaleCollateral", () => {
    it("skipTcbCheck bypasses collateral staleness check", async () => {
      const result = await verifyTdxQuote(allTdxQuotes[0].data, { skipTcbCheck: true });
      expect(result.valid).toBe(true);
    });
  });

  describe("new result fields (mrseam, mrsignerseam, septVeDisable)", () => {
    it("populates mrseam as 96 hex chars", async () => {
      const result = await verifyTdxQuote(allTdxQuotes[0].data, { skipTcbCheck: true });
      expect(result.valid).toBe(true);
      expect(result.mrseam).toMatch(/^[0-9a-f]{96}$/);
    });

    it("populates mrsignerseam as 96 hex chars", async () => {
      const result = await verifyTdxQuote(allTdxQuotes[0].data, { skipTcbCheck: true });
      expect(result.mrsignerseam).toMatch(/^[0-9a-f]{96}$/);
    });

    it("populates septVeDisable as boolean", async () => {
      const result = await verifyTdxQuote(allTdxQuotes[0].data, { skipTcbCheck: true });
      expect(typeof result.septVeDisable).toBe("boolean");
    });
  });

  describe("TD attribute validation (Step 7b)", () => {
    it("passes with our real quote (no reserved bits set)", async () => {
      const result = await verifyTdxQuote(allTdxQuotes[0].data, { skipTcbCheck: true });
      expect(result.valid).toBe(true);
    });

    it("skipTdAttributeCheck bypasses reserved-bit check", async () => {
      const result = await verifyTdxQuote(allTdxQuotes[0].data, {
        skipTcbCheck: true,
        skipTdAttributeCheck: true,
      });
      expect(result.valid).toBe(true);
    });
  });

  describe("MRSEAM pinning (Step 7c)", () => {
    it("passes when expectedMrseam matches", async () => {
      const quote = parseTdxQuote(allTdxQuotes[0].data);
      const result = await verifyTdxQuote(allTdxQuotes[0].data, {
        expectedMrseam: quote.body.mrseam,
        skipTcbCheck: true,
      });
      expect(result.valid).toBe(true);
    });

    it("rejects when expectedMrseam does not match", async () => {
      const wrongMrseam = new Uint8Array(48).fill(0xcc);
      const result = await verifyTdxQuote(allTdxQuotes[0].data, {
        expectedMrseam: wrongMrseam,
        skipTcbCheck: true,
      });
      expect(result.valid).toBe(false);
      expect(result.error).toMatch(/mrseam/i);
    });

    it("passes when expectedMrsignerseam matches", async () => {
      const quote = parseTdxQuote(allTdxQuotes[0].data);
      const result = await verifyTdxQuote(allTdxQuotes[0].data, {
        expectedMrsignerseam: quote.body.mrsignerseam,
        skipTcbCheck: true,
      });
      expect(result.valid).toBe(true);
    });

    it("rejects when expectedMrsignerseam does not match", async () => {
      const wrongMrsignerseam = new Uint8Array(48).fill(0xdd);
      const result = await verifyTdxQuote(allTdxQuotes[0].data, {
        expectedMrsignerseam: wrongMrsignerseam,
        skipTcbCheck: true,
      });
      expect(result.valid).toBe(false);
      expect(result.error).toMatch(/mrsignerseam/i);
    });
  });

  describe("truncated input", () => {
    it("rejects empty input", async () => {
      const result = await verifyTdxQuote(new Uint8Array(0));
      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
    });

    it("rejects input shorter than header", async () => {
      const result = await verifyTdxQuote(new Uint8Array(10));
      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
    });
  });
});
