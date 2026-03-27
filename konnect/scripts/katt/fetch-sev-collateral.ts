/**
 * Fetch fresh AMD SEV-SNP CRLs from AMD KDS.
 *
 * Run: bun run scripts/katt/fetch-sev-collateral.ts
 *
 * Then commit the updated src/sev/collateral.generated.ts.
 */

import { writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUTPUT = resolve(__dirname, '../../src/katt/sev/collateral.generated.ts');

const KDS_BASE = 'https://kdsintf.amd.com/vcek/v1';
const PRODUCTS = ['Milan', 'Genoa', 'Turin'];

async function fetchBinary(url: string): Promise<Uint8Array> {
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} from ${url}`);
  }
  return new Uint8Array(await res.arrayBuffer());
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function main() {
  console.log('Fetching AMD SEV-SNP CRLs...');

  const crls: Record<string, string> = {};

  for (const product of PRODUCTS) {
    const url = `${KDS_BASE}/${product}/crl`;
    console.log(`  ${product} CRL from ${url}...`);
    const crlDer = await fetchBinary(url);
    crls[product] = toHex(crlDer);
    console.log(`    ${crlDer.length} bytes`);
  }

  const output = `// Auto-generated — re-run: npx tsx scripts/fetch-sev-collateral.ts
// Generated: ${new Date().toISOString()}

function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export interface SevCollateralData {
  crls: Record<string, Uint8Array>;
  fetchedAt: string;
}

const data: SevCollateralData = {
  crls: {
${PRODUCTS.map(p => `    '${p}': fromHex('${crls[p]}'),`).join('\n')}
  },
  fetchedAt: '${new Date().toISOString()}',
};

export default data;
`;

  writeFileSync(OUTPUT, output);
  console.log(`\nWrote ${OUTPUT}`);
  console.log(`  ${PRODUCTS.length} product CRLs`);
}

main().catch(err => {
  console.error('Failed to fetch SEV collateral:', err);
  process.exit(1);
});
