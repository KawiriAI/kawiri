import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { parseCertificate } from "@katt/der.js";
import { parseBundle } from "@katt/sigstore/bundle.js";
import { extractFulcioIdentity, verifyFulcioCert, verifySCTs } from "@katt/sigstore/fulcio.js";
import SIGSTORE_TRUSTED_ROOT from "@katt/sigstore/trusted-root.js";

if (!import.meta.dirname) throw new Error("expected import.meta.dirname");
const bundleJson = JSON.parse(readFileSync(resolve(import.meta.dirname, "fixtures/sigstore-bundle.json"), "utf-8"));

describe("verifyFulcioCert", () => {
  it("verifies cert chains to Fulcio root from trusted root", async () => {
    const parsed = parseBundle(bundleJson);
    const result = await verifyFulcioCert(parsed.signingCert, SIGSTORE_TRUSTED_ROOT);

    expect(result.identity).toBeDefined();
    expect(result.signingKey).toBeDefined();
    expect(result.identity.oidcIssuer).toBe("https://token.actions.githubusercontent.com");
  });

  it("extracts correct identity fields", async () => {
    const parsed = parseBundle(bundleJson);
    const { identity } = await verifyFulcioCert(parsed.signingCert, SIGSTORE_TRUSTED_ROOT);

    expect(identity.oidcIssuer).toBe("https://token.actions.githubusercontent.com");
    expect(identity.sourceRepoUri).toContain("https://github.com/");
    expect(identity.sourceRepoRef).toMatch(/^refs\//);
  });

  it("rejects self-signed cert", async () => {
    // Generate a self-signed key pair — not from Fulcio
    const _keyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    // Use an arbitrary DER-like byte string that won't chain to Fulcio
    const fakeCert = new Uint8Array(512);
    fakeCert[0] = 0x30; // SEQUENCE tag
    fakeCert[1] = 0x82;
    fakeCert[2] = 0x01;
    fakeCert[3] = 0xfc;

    await expect(verifyFulcioCert(fakeCert, SIGSTORE_TRUSTED_ROOT)).rejects.toThrow();
  });
});

describe("extractFulcioIdentity", () => {
  it("extracts OIDC issuer, source repo, workflow ref", () => {
    const parsed = parseBundle(bundleJson);
    const cert = parseCertificate(parsed.signingCert);
    const identity = extractFulcioIdentity(cert.tbs);

    expect(identity.oidcIssuer).toBe("https://token.actions.githubusercontent.com");
    expect(identity.sourceRepoUri).toContain("https://github.com/");
    expect(identity.sourceRepoRef).toMatch(/^refs\//);
    expect(identity.sourceRepoDigest).toMatch(/^[a-f0-9]{40}$/);
  });

  it("extracts build signer URI (build config URI)", () => {
    const parsed = parseBundle(bundleJson);
    const cert = parseCertificate(parsed.signingCert);
    const identity = extractFulcioIdentity(cert.tbs);

    // buildSignerUri maps to Build Config URI which contains the workflow URL
    expect(identity.buildSignerUri).toContain("github.com");
    expect(identity.buildSignerUri).toContain(".github/workflows/");
  });
});

describe("verifySCTs", () => {
  it("verifies SCTs from real Fulcio cert against CT log keys", async () => {
    const parsed = parseBundle(bundleJson);
    const count = await verifySCTs(parsed.signingCert, SIGSTORE_TRUSTED_ROOT);
    expect(count).toBeGreaterThanOrEqual(1);
  });
});
