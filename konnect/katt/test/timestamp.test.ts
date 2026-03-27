import { describe, expect, it } from "bun:test";
import { verifyRFC3161Timestamps } from "@katt/sigstore/timestamp.js";
import SIGSTORE_TRUSTED_ROOT from "@katt/sigstore/trusted-root.js";
import { b64Decode } from "@katt/util.js";

/**
 * Real CMS TimeStampToken from Sigstore TSA (timestamp.sigstore.dev).
 * Signed with ECDSA P-384 key, SHA-256 digest.
 * TSA cert: O=sigstore.dev, CN=sigstore-tsa
 * Issuer: O=sigstore.dev, CN=sigstore-tsa-selfsigned
 * No embedded certificates (certs must come from trusted root).
 */
const REAL_TSA_TOKEN_B64 =
  "MIICwQYJKoZIhvcNAQcCoIICsjCCAq4CAQMxDTALBglghkgBZQMEAgEwgbgGCyqGSIb3DQEJEAEEoIGoBIGlMIGiAgEBBgkrBgEEAYO/MAIwMTANBglghkgBZQMEAgEFAAQggY8GllnqeJ1DoIq0/H5VkNshe9k9IE9qoRw0v8mYqGsCFQCYXw2lPEfXn8bszA9BXToIgxpYkRgPMjAyNjAyMTgyMTM3NDVaMAMCAQGgMqQwMC4xFTATBgNVBAoTDHNpZ3N0b3JlLmRldjEVMBMGA1UEAxMMc2lnc3RvcmUtdHNhoAAxggHbMIIB1wIBATBRMDkxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjEgMB4GA1UEAxMXc2lnc3RvcmUtdHNhLXNlbGZzaWduZWQCFDoTVC8MkGHuvMFDL8uKjosqI4sMMAsGCWCGSAFlAwQCAaCB/DAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTI2MDIxODIxMzc0NVowLwYJKoZIhvcNAQkEMSIEIEEgdZERL8mJuSUABjgDrUvnjKymAooqgFfGPd5ocEl8MIGOBgsqhkiG9w0BCRACLzF/MH0wezB5BCCF+Se8B6tiysO0Q1bBDvyBssaIP9p6uebYcNnROs0FtzBVMD2kOzA5MRUwEwYDVQQKEwxzaWdzdG9yZS5kZXYxIDAeBgNVBAMTF3NpZ3N0b3JlLXRzYS1zZWxmc2lnbmVkAhQ6E1QvDJBh7rzBQy/Lio6LKiOLDDAKBggqhkjOPQQDAgRnMGUCMGTWkFa5NnOpIHOG5UjHzEO2kqPy5yKNUHxQMSvIVmC5HBMu6wDO2Pp/CBD3GmYUXgIxAMYGGG7GL2HgvW7UIThCopW/SgENZQEzzeR4P5gT7+hAk1nB5ncjo1dzGj9s+qRabw==";

describe("verifyRFC3161Timestamps", () => {
  const token = b64Decode(REAL_TSA_TOKEN_B64);

  it("verifies real Sigstore TSA token → returns valid Date", async () => {
    const dates = await verifyRFC3161Timestamps([token], SIGSTORE_TRUSTED_ROOT);
    expect(dates.length).toBe(1);
    expect(dates[0]).toBeInstanceOf(Date);
    // Token was signed on 2026-02-18
    expect(dates[0].getUTCFullYear()).toBe(2026);
    expect(dates[0].getUTCMonth()).toBe(1); // February = 1
    expect(dates[0].getUTCDate()).toBe(18);
  });

  it("rejects token with corrupted signature", async () => {
    const corrupted = new Uint8Array(token);
    // Flip a byte near the end (in the ECDSA signature)
    corrupted[corrupted.length - 10] ^= 0xff;
    const dates = await verifyRFC3161Timestamps([corrupted], SIGSTORE_TRUSTED_ROOT);
    expect(dates.length).toBe(0);
  });

  it("rejects token when no matching TSA cert in trusted root", async () => {
    const emptyRoot = { ...SIGSTORE_TRUSTED_ROOT, timestampAuthorities: [] };
    const dates = await verifyRFC3161Timestamps([token], emptyRoot);
    expect(dates.length).toBe(0);
  });

  it("returns empty array for malformed input", async () => {
    const garbage = new Uint8Array([0x30, 0x03, 0x01, 0x01, 0xff]);
    const dates = await verifyRFC3161Timestamps([garbage], SIGSTORE_TRUSTED_ROOT);
    expect(dates.length).toBe(0);
  });

  it("returns empty array for empty input", async () => {
    const dates = await verifyRFC3161Timestamps([], SIGSTORE_TRUSTED_ROOT);
    expect(dates.length).toBe(0);
  });

  it("rejects token when artifact signature does not match messageImprint", async () => {
    // Pass a wrong artifact signature — messageImprint won't match SHA-256(wrong)
    const wrongSignature = new Uint8Array(64).fill(0xaa);
    const dates = await verifyRFC3161Timestamps([token], SIGSTORE_TRUSTED_ROOT, wrongSignature);
    expect(dates.length).toBe(0);
  });

  it("accepts token when no artifact signature is provided (no binding check)", async () => {
    // Without artifactSignature, messageImprint binding is skipped
    const dates = await verifyRFC3161Timestamps([token], SIGSTORE_TRUSTED_ROOT);
    expect(dates.length).toBe(1);
  });
});
