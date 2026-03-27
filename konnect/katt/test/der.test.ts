import { describe, expect, it } from "bun:test";
import { parsePemChain } from "@katt/cert.js";
import {
  derSignatureToRaw,
  detectSignatureAlgorithm,
  extractExtensions,
  extractSerialNumber,
  extractSpki,
  findExtensionByOid,
  iterateSequenceChildren,
  parseCertificate,
  readTL,
} from "@katt/der.js";
import { parseTdxQuote } from "@katt/tdx/parse.js";
import { ARK_GENOA_PEM, ASK_GENOA_PEM, allTdxQuotes, hasTdxFixtures, intelRootCaDer } from "./fixtures.js";

function getFirstQuote() {
  return hasTdxFixtures ? allTdxQuotes[0] : undefined;
}

describe("readTL", () => {
  it("reads short-form length", () => {
    const buf = new Uint8Array([0x30, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05]);
    const tl = readTL(buf, 0);
    expect(tl.tag).toBe(0x30);
    expect(tl.length).toBe(5);
    expect(tl.headerSize).toBe(2);
  });

  it("reads 0x81 length", () => {
    // 3-byte header + 128 bytes of content
    const buf = new Uint8Array(3 + 128);
    buf[0] = 0x30;
    buf[1] = 0x81;
    buf[2] = 0x80;
    const tl = readTL(buf, 0);
    expect(tl.tag).toBe(0x30);
    expect(tl.length).toBe(128);
    expect(tl.headerSize).toBe(3);
  });

  it("reads 0x82 length", () => {
    // 4-byte header + 0x028f bytes of content
    const buf = new Uint8Array(4 + 0x028f);
    buf[0] = 0x30;
    buf[1] = 0x82;
    buf[2] = 0x02;
    buf[3] = 0x8f;
    const tl = readTL(buf, 0);
    expect(tl.tag).toBe(0x30);
    expect(tl.length).toBe(0x028f);
    expect(tl.headerSize).toBe(4);
  });

  it("rejects TLV extending beyond buffer", () => {
    // Header claims 128 bytes but buffer only has 3 bytes
    const buf = new Uint8Array([0x30, 0x81, 0x80]);
    expect(() => readTL(buf, 0)).toThrow(/extends beyond buffer/);
  });
});

describe("parseCertificate - Intel Root CA", () => {
  it("extracts TBS as a SEQUENCE", () => {
    const cert = parseCertificate(intelRootCaDer);
    expect(cert.tbs[0]).toBe(0x30); // SEQUENCE tag
    expect(cert.tbs.length).toBeGreaterThan(0);
  });

  it("extracts a valid signature", () => {
    const cert = parseCertificate(intelRootCaDer);
    // ECDSA P-256 DER signature is typically 70-72 bytes
    expect(cert.signature.length).toBeGreaterThanOrEqual(64);
    expect(cert.signature.length).toBeLessThanOrEqual(72);
  });

  it("extracts signature algorithm", () => {
    const cert = parseCertificate(intelRootCaDer);
    expect(cert.signatureAlgorithm[0]).toBe(0x30); // SEQUENCE
  });
});

describe("detectSignatureAlgorithm", () => {
  it("detects Intel Root CA as ecdsa-p256-sha256", () => {
    const cert = parseCertificate(intelRootCaDer);
    expect(detectSignatureAlgorithm(cert.signatureAlgorithm)).toBe("ecdsa-p256-sha256");
  });

  it("detects AMD ARK-Genoa as rsa-pss-sha384", () => {
    const arkDer = parsePemChain(ARK_GENOA_PEM)[0];
    const cert = parseCertificate(arkDer);
    expect(detectSignatureAlgorithm(cert.signatureAlgorithm)).toBe("rsa-pss-sha384");
  });

  it("detects AMD ASK-Genoa as rsa-pss-sha384", () => {
    const askDer = parsePemChain(ASK_GENOA_PEM)[0];
    const cert = parseCertificate(askDer);
    expect(detectSignatureAlgorithm(cert.signatureAlgorithm)).toBe("rsa-pss-sha384");
  });
});

describe("extractSpki", () => {
  it("extracts SPKI from Intel Root CA as a SEQUENCE", () => {
    const cert = parseCertificate(intelRootCaDer);
    const spki = extractSpki(cert.tbs);
    expect(spki[0]).toBe(0x30); // SEQUENCE
    // P-256 SPKI is typically 91 bytes
    expect(spki.length).toBeGreaterThanOrEqual(59);
  });

  it("extracts SPKI from AMD ARK-Genoa", () => {
    const arkDer = parsePemChain(ARK_GENOA_PEM)[0];
    const cert = parseCertificate(arkDer);
    const spki = extractSpki(cert.tbs);
    expect(spki[0]).toBe(0x30); // SEQUENCE
    // RSA-4096 SPKI is much larger
    expect(spki.length).toBeGreaterThan(500);
  });
});

describe("parseCertificate - AMD ARK-Genoa", () => {
  it("extracts TBS as a SEQUENCE", () => {
    const arkDer = parsePemChain(ARK_GENOA_PEM)[0];
    const cert = parseCertificate(arkDer);
    expect(cert.tbs[0]).toBe(0x30);
    expect(cert.tbs.length).toBeGreaterThan(0);
  });

  it("extracts a valid RSA-PSS signature", () => {
    const arkDer = parsePemChain(ARK_GENOA_PEM)[0];
    const cert = parseCertificate(arkDer);
    // RSA-4096 signature is 512 bytes
    expect(cert.signature.length).toBe(512);
  });
});

describe("derSignatureToRaw", () => {
  it("converts a standard DER signature (no leading zeros)", () => {
    const r = new Uint8Array(32).fill(0x42);
    const s = new Uint8Array(32).fill(0x13);
    r[0] = 0x7f;
    s[0] = 0x7f;

    const der = new Uint8Array([0x30, 2 + 32 + 2 + 32, 0x02, 32, ...r, 0x02, 32, ...s]);

    const raw = derSignatureToRaw(der, 32);
    expect(raw.length).toBe(64);
    expect(raw.slice(0, 32)).toEqual(r);
    expect(raw.slice(32, 64)).toEqual(s);
  });

  it("strips leading 0x00 from DER integers", () => {
    const r = new Uint8Array([0x00, 0x80, ...new Uint8Array(31).fill(0x42)]);
    const s = new Uint8Array([0x00, 0x90, ...new Uint8Array(31).fill(0x13)]);

    const der = new Uint8Array([0x30, 2 + 33 + 2 + 33, 0x02, 33, ...r, 0x02, 33, ...s]);

    const raw = derSignatureToRaw(der, 32);
    expect(raw.length).toBe(64);
    expect(raw[0]).toBe(0x80);
    expect(raw[32]).toBe(0x90);
  });

  it("pads short DER integers", () => {
    const r = new Uint8Array([0x01, 0x02, 0x03]);
    const s = new Uint8Array([0x04, 0x05]);

    const der = new Uint8Array([0x30, 2 + 3 + 2 + 2, 0x02, 3, ...r, 0x02, 2, ...s]);

    const raw = derSignatureToRaw(der, 32);
    expect(raw.length).toBe(64);
    expect(raw[29]).toBe(0x01);
    expect(raw[30]).toBe(0x02);
    expect(raw[31]).toBe(0x03);
    expect(raw[0]).toBe(0x00);
    expect(raw[62]).toBe(0x04);
    expect(raw[63]).toBe(0x05);
    expect(raw[32]).toBe(0x00);
  });

  it("handles P-384 component size", () => {
    const r = new Uint8Array(48).fill(0x42);
    const s = new Uint8Array(48).fill(0x13);
    r[0] = 0x7f;
    s[0] = 0x7f;

    const der = new Uint8Array([0x30, 2 + 48 + 2 + 48, 0x02, 48, ...r, 0x02, 48, ...s]);

    const raw = derSignatureToRaw(der, 48);
    expect(raw.length).toBe(96);
    expect(raw.slice(0, 48)).toEqual(r);
    expect(raw.slice(48, 96)).toEqual(s);
  });
});

describe("extractExtensions", () => {
  it("extracts extensions from Intel Root CA", () => {
    const cert = parseCertificate(intelRootCaDer);
    const exts = extractExtensions(cert.tbs);
    expect(exts.length).toBeGreaterThanOrEqual(3);
    // Every extension should have an OID and a value
    for (const ext of exts) {
      expect(ext.oid.length).toBeGreaterThan(0);
      expect(ext.value.length).toBeGreaterThan(0);
    }
  });

  it("extracts extensions from a PCK cert", () => {
    const firstQuote = getFirstQuote();
    if (!firstQuote) return;
    const quote = parseTdxQuote(firstQuote.data);
    const pemString = new TextDecoder().decode(quote.qeReportCertData.certChain);
    const certs = parsePemChain(pemString);
    const pckCert = parseCertificate(certs[0]);
    const exts = extractExtensions(pckCert.tbs);
    // PCK certs have SGX-specific extensions — typically 7+
    expect(exts.length).toBeGreaterThanOrEqual(3);
  });

  it("can find Subject Key Identifier by OID", () => {
    const cert = parseCertificate(intelRootCaDer);
    const exts = extractExtensions(cert.tbs);
    // OID 2.5.29.14 = Subject Key Identifier
    const skiOid = new Uint8Array([0x55, 0x1d, 0x0e]);
    const ski = findExtensionByOid(exts, skiOid);
    expect(ski).toBeDefined();
    expect(ski?.value.length).toBeGreaterThan(0);
  });

  it("returns undefined for unknown OID", () => {
    const cert = parseCertificate(intelRootCaDer);
    const exts = extractExtensions(cert.tbs);
    const fakeOid = new Uint8Array([0xff, 0xff, 0xff]);
    expect(findExtensionByOid(exts, fakeOid)).toBeUndefined();
  });
});

describe("extractSerialNumber", () => {
  it("extracts serial from Intel Root CA", () => {
    const cert = parseCertificate(intelRootCaDer);
    const serial = extractSerialNumber(cert.tbs);
    expect(serial.length).toBeGreaterThan(0);
    // Serial should be a positive integer (no all-zero)
    expect(serial.some((b) => b !== 0)).toBe(true);
  });

  it("extracts serial from PCK cert", () => {
    const firstQuote = getFirstQuote();
    if (!firstQuote) return;
    const quote = parseTdxQuote(firstQuote.data);
    const pemString = new TextDecoder().decode(quote.qeReportCertData.certChain);
    const certs = parsePemChain(pemString);
    const pckCert = parseCertificate(certs[0]);
    const serial = extractSerialNumber(pckCert.tbs);
    expect(serial.length).toBeGreaterThan(0);
  });
});

describe("iterateSequenceChildren", () => {
  it("iterates children of a SEQUENCE", () => {
    // Build: SEQUENCE { INTEGER 0x42, BOOLEAN true }
    const data = new Uint8Array([
      0x30,
      0x06, // SEQUENCE, 6 bytes
      0x02,
      0x01,
      0x42, // INTEGER, 1 byte, value 0x42
      0x01,
      0x01,
      0xff, // BOOLEAN, 1 byte, true
    ]);
    const children = [...iterateSequenceChildren(data)];
    expect(children.length).toBe(2);
    expect(children[0].tag).toBe(0x02);
    expect(children[1].tag).toBe(0x01);
  });
});

describe("parseCertificate - PCK cert from quote", () => {
  it("parses a PCK cert extracted from a real quote", () => {
    const firstQuote = getFirstQuote();
    if (!firstQuote) return;
    const quote = parseTdxQuote(firstQuote.data);
    const pemString = new TextDecoder().decode(quote.qeReportCertData.certChain);
    const certs = parsePemChain(pemString);
    expect(certs.length).toBeGreaterThanOrEqual(2);

    const pckCert = parseCertificate(certs[0]);
    expect(pckCert.tbs[0]).toBe(0x30);
    expect(pckCert.signature.length).toBeGreaterThanOrEqual(64);

    const spki = extractSpki(pckCert.tbs);
    expect(spki[0]).toBe(0x30);
  });
});
