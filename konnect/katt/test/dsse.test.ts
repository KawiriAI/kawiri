import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { extractSpki, parseCertificate } from "@katt/der.js";
import { parseBundle } from "@katt/sigstore/bundle.js";
import { preAuthEncoding, verifyDSSESignature } from "@katt/sigstore/dsse.js";

if (!import.meta.dirname) throw new Error("expected import.meta.dirname");
const bundleJson = JSON.parse(readFileSync(resolve(import.meta.dirname, "fixtures/sigstore-bundle.json"), "utf-8"));

describe("preAuthEncoding", () => {
  it("produces correct PAE for known payloadType + payload", () => {
    const payloadType = "application/vnd.in-toto+json";
    const payload = new TextEncoder().encode('{"test": true}');
    const pae = preAuthEncoding(payloadType, payload);
    const paeStr = new TextDecoder().decode(pae);

    // Should start with "DSSEv1 {typeLen} {type} {payloadLen} "
    expect(paeStr).toContain("DSSEv1");
    expect(paeStr).toContain(payloadType);
    // Byte length of payloadType
    expect(paeStr).toContain(`${new TextEncoder().encode(payloadType).length}`);
  });

  it("uses byte lengths not string lengths", () => {
    // Use a multi-byte character payload type
    const payloadType = "application/vnd.in-toto+json";
    const payload = new Uint8Array([1, 2, 3, 4, 5]);
    const pae = preAuthEncoding(payloadType, payload);
    const paeStr = new TextDecoder().decode(pae.slice(0, pae.length - 5));

    // The payload length should be 5 (byte length)
    expect(paeStr).toContain(" 5 ");
  });

  it("ends with payload bytes after trailing space", () => {
    const payloadType = "test";
    const payload = new Uint8Array([0xaa, 0xbb]);
    const pae = preAuthEncoding(payloadType, payload);

    // Last 2 bytes should be the payload
    expect(pae[pae.length - 2]).toBe(0xaa);
    expect(pae[pae.length - 1]).toBe(0xbb);
  });

  it('format matches "DSSEv1 {typeLen} {type} {payloadLen} {payload}"', () => {
    const payloadType = "text/plain";
    const payload = new TextEncoder().encode("hello");
    const pae = preAuthEncoding(payloadType, payload);
    const decoded = new TextDecoder().decode(pae);
    // "DSSEv1 10 text/plain 5 hello"
    expect(decoded).toBe("DSSEv1 10 text/plain 5 hello");
  });
});

describe("verifyDSSESignature", () => {
  it("verifies DSSE signature from real bundle", async () => {
    const parsed = parseBundle(bundleJson);
    const cert = parseCertificate(parsed.signingCert);
    const spki = extractSpki(cert.tbs);
    const key = await crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    const result = await verifyDSSESignature(parsed.envelope, key);
    expect(result).toBe(true);
  });

  it("rejects corrupted signature", async () => {
    const parsed = parseBundle(bundleJson);
    const cert = parseCertificate(parsed.signingCert);
    const spki = extractSpki(cert.tbs);
    const key = await crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);

    // Corrupt the signature
    const corrupted = { ...parsed.envelope };
    corrupted.signature = new Uint8Array(parsed.envelope.signature);
    corrupted.signature[10] ^= 0xff;

    await expect(verifyDSSESignature(corrupted, key)).rejects.toThrow(/signature/i);
  });

  it("rejects wrong payload", async () => {
    const parsed = parseBundle(bundleJson);
    const cert = parseCertificate(parsed.signingCert);
    const spki = extractSpki(cert.tbs);
    const key = await crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);

    // Modify payload
    const wrongPayload = {
      ...parsed.envelope,
      payload: new TextEncoder().encode('{"wrong": true}'),
    };

    await expect(verifyDSSESignature(wrongPayload, key)).rejects.toThrow(/signature/i);
  });
});
