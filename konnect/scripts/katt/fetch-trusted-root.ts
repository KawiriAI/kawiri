/**
 * Fetch the latest Sigstore trusted root and generate trusted-root.ts.
 *
 * Run: bun run scripts/katt/fetch-trusted-root.ts
 *
 * Then commit the updated src/sigstore/trusted-root.ts.
 */

import { writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUTPUT = resolve(__dirname, '../../src/katt/sigstore/trusted-root.ts');

const TRUSTED_ROOT_URL =
  'https://raw.githubusercontent.com/sigstore/root-signing/main/targets/trusted_root.json';

interface TlogEntry {
  baseUrl: string;
  hashAlgorithm: string;
  publicKey: { rawBytes: string; keyDetails: string; validFor: { start: string; end?: string } };
  logId: { keyId: string };
}

interface CaEntry {
  subject: { organization: string; commonName: string };
  uri: string;
  certChain: { certificates: { rawBytes: string }[] };
  validFor: { start: string; end?: string };
}

async function main() {
  console.log('Fetching Sigstore trusted root...');
  const res = await fetch(TRUSTED_ROOT_URL);
  if (!res.ok) throw new Error(`HTTP ${res.status} from ${TRUSTED_ROOT_URL}`);
  const root = await res.json();

  console.log(`  tlogs: ${root.tlogs.length}`);
  console.log(`  certificateAuthorities: ${root.certificateAuthorities.length}`);
  console.log(`  ctlogs: ${root.ctlogs.length}`);
  console.log(`  timestampAuthorities: ${root.timestampAuthorities.length}`);

  const mapped = {
    tlogs: root.tlogs.map((t: TlogEntry) => ({
      baseUrl: t.baseUrl,
      hashAlgorithm: t.hashAlgorithm,
      publicKey: {
        rawBytes: t.publicKey.rawBytes,
        keyDetails: t.publicKey.keyDetails,
        validFor: t.publicKey.validFor,
      },
      logId: { keyId: t.logId.keyId },
    })),
    certificateAuthorities: root.certificateAuthorities.map((ca: CaEntry) => ({
      subject: ca.subject,
      uri: ca.uri,
      certChain: {
        certificates: ca.certChain.certificates.map((c: { rawBytes: string }) => ({ rawBytes: c.rawBytes })),
      },
      validFor: ca.validFor,
    })),
    ctlogs: root.ctlogs.map((ct: TlogEntry) => ({
      baseUrl: ct.baseUrl,
      hashAlgorithm: ct.hashAlgorithm,
      publicKey: {
        rawBytes: ct.publicKey.rawBytes,
        keyDetails: ct.publicKey.keyDetails,
        validFor: ct.publicKey.validFor,
      },
      logId: { keyId: ct.logId.keyId },
    })),
    timestampAuthorities: root.timestampAuthorities.map((tsa: CaEntry) => ({
      subject: tsa.subject,
      uri: tsa.uri,
      certChain: {
        certificates: tsa.certChain.certificates.map((c: { rawBytes: string }) => ({ rawBytes: c.rawBytes })),
      },
      validFor: tsa.validFor,
    })),
  };

  const output = `// Auto-generated — re-run: bun run scripts/katt/fetch-trusted-root.ts
// Generated: ${new Date().toISOString()}
// Source: ${TRUSTED_ROOT_URL}

import type { TrustedRoot } from './types.js';

const SIGSTORE_TRUSTED_ROOT: TrustedRoot = ${JSON.stringify(mapped, null, 2)};

export default SIGSTORE_TRUSTED_ROOT;
`;

  writeFileSync(OUTPUT, output);
  console.log(`\nWrote ${OUTPUT}`);
}

main().catch(err => {
  console.error('Failed to fetch trusted root:', err);
  process.exit(1);
});
