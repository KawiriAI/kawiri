/**
 * Fetch fresh Intel TDX collateral from the Intel PCS API.
 *
 * Run: bun run scripts/katt/fetch-collateral.ts
 *
 * Then commit the updated src/tdx/collateral.generated.ts.
 */

import { writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUTPUT = resolve(__dirname, '../../src/katt/tdx/collateral.generated.ts');

const PCS_BASE = 'https://api.trustedservices.intel.com';

// Known FMSPCs to fetch collateral for
const FMSPCS = [
  '70A06D070000', // Intel Xeon 6527P Granite Rapids (our TDX host)
];

interface CollateralEntry {
  fmspc: string;
  tcbInfoJson: string;
  tcbInfoSignature: string;
  issueDate: string;
  nextUpdate: string;
}

async function fetchJson(url: string): Promise<{ body: string; headers: Headers }> {
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} from ${url}: ${await res.text()}`);
  }
  return { body: await res.text(), headers: res.headers };
}

async function fetchBinary(url: string): Promise<{ data: Uint8Array; headers: Headers }> {
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} from ${url}`);
  }
  return { data: new Uint8Array(await res.arrayBuffer()), headers: res.headers };
}

function decodeHeaderChain(headers: Headers, name: string): string | undefined {
  const val = headers.get(name);
  return val ? decodeURIComponent(val) : undefined;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function main() {
  console.log('Fetching Intel TDX collateral...');

  const entries: CollateralEntry[] = [];
  let lastTcbHeaders: Headers | undefined;

  for (const fmspc of FMSPCS) {
    console.log(`  TCB Info for FMSPC ${fmspc}...`);
    const { body: tcbInfoBody, headers: tcbHeaders } = await fetchJson(
      `${PCS_BASE}/tdx/certification/v4/tcb?fmspc=${fmspc}`
    );

    // IMPORTANT: preserve raw JSON bytes — signatures are computed over exact bytes
    const parsed = JSON.parse(tcbInfoBody);

    // Extract the raw tcbInfo JSON string using regex to preserve exact bytes
    const tcbInfoMatch = tcbInfoBody.match(/"tcbInfo"\s*:\s*(\{[\s\S]*\})\s*,\s*"signature"/);
    if (!tcbInfoMatch) {
      throw new Error(`Could not extract tcbInfo JSON for FMSPC ${fmspc}`);
    }
    const tcbInfoJson = tcbInfoMatch[1];
    const tcbInfoSignature = parsed.signature;
    const tcbInfo = JSON.parse(tcbInfoJson);

    lastTcbHeaders = tcbHeaders;

    entries.push({
      fmspc,
      tcbInfoJson,
      tcbInfoSignature,
      issueDate: tcbInfo.issueDate,
      nextUpdate: tcbInfo.nextUpdate,
    });

    console.log(`    Status: ${tcbInfo.tcbLevels?.[0]?.tcbStatus ?? 'unknown'}`);
    console.log(`    Issue: ${tcbInfo.issueDate}, Next: ${tcbInfo.nextUpdate}`);
  }

  // Fetch QE Identity
  console.log('  QE Identity...');
  const { body: qeIdentityBody, headers: qeHeaders } = await fetchJson(
    `${PCS_BASE}/tdx/certification/v4/qe/identity`
  );
  const qeIdentityParsed = JSON.parse(qeIdentityBody);
  const qeIdentityMatch = qeIdentityBody.match(/"enclaveIdentity"\s*:\s*(\{[\s\S]*\})\s*,\s*"signature"/);
  const qeIdentityJson = qeIdentityMatch ? qeIdentityMatch[1] : JSON.stringify(qeIdentityParsed.enclaveIdentity);
  const qeIdentitySignature = qeIdentityParsed.signature;

  // Fetch PCK CRL (DER) — use platform CA since our Granite Rapids uses Platform CA
  console.log('  PCK CRL...');
  const { data: pckCrlDer, headers: crlHeaders } = await fetchBinary(
    `${PCS_BASE}/sgx/certification/v4/pckcrl?ca=platform&encoding=der`
  );
  console.log(`    PCK CRL: ${pckCrlDer.length} bytes`);

  // Fetch Root CA CRL (DER) — for checking intermediate cert revocation
  // The PCS /rootcacrl endpoint may 404; use the direct cert URL instead.
  // The file at this URL is PEM-encoded — we need to strip headers and base64-decode.
  console.log('  Root CA CRL...');
  let rootCaCrlDer: Uint8Array | undefined;
  try {
    const rootCrlRes = await fetch('https://certificates.trustedservices.intel.com/IntelSGXRootCA.der');
    if (rootCrlRes.ok) {
      const contentType = rootCrlRes.headers.get('content-type') ?? '';
      const rawBytes = new Uint8Array(await rootCrlRes.arrayBuffer());
      // Check if response is PEM (starts with "-----")
      const firstFiveChars = new TextDecoder().decode(rawBytes.subarray(0, 5));
      if (firstFiveChars === '-----') {
        // PEM-encoded CRL — strip headers and base64-decode
        const pem = new TextDecoder().decode(rawBytes);
        const b64 = pem.replace(/-----[A-Z ]+-----/g, '').replace(/\s/g, '');
        const binaryString = atob(b64);
        rootCaCrlDer = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
          rootCaCrlDer[i] = binaryString.charCodeAt(i);
        }
      } else {
        rootCaCrlDer = rawBytes;
      }
      console.log(`    Root CA CRL: ${rootCaCrlDer.length} bytes (DER)`);
    } else {
      console.log(`    Root CA CRL: HTTP ${rootCrlRes.status} (skipped)`);
    }
  } catch (err) {
    console.log(`    Root CA CRL: fetch failed (skipped): ${err}`);
  }

  // Capture issuer chain headers (PEM certs, URL-encoded)
  const tcbInfoIssuerChain = lastTcbHeaders
    ? (decodeHeaderChain(lastTcbHeaders, 'TCB-Info-Issuer-Chain')
      ?? decodeHeaderChain(lastTcbHeaders, 'Sgx-TCB-Info-Issuer-Chain'))
    : undefined;
  const qeIdentityIssuerChain = decodeHeaderChain(qeHeaders, 'Sgx-Enclave-Identity-Issuer-Chain');
  const pckCrlIssuerChain = decodeHeaderChain(crlHeaders, 'Sgx-PCK-CRL-Issuer-Chain');

  console.log(`    TCB Info issuer chain: ${tcbInfoIssuerChain ? 'present' : 'absent'}`);
  console.log(`    QE Identity issuer chain: ${qeIdentityIssuerChain ? 'present' : 'absent'}`);
  console.log(`    PCK CRL issuer chain: ${pckCrlIssuerChain ? 'present' : 'absent'}`);

  // Generate output file
  const output = `// Auto-generated — re-run scripts/fetch-collateral.ts to refresh
// Generated: ${new Date().toISOString()}

function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export interface CollateralData {
  entries: Array<{
    fmspc: string;
    tcbInfoJson: string;
    tcbInfoSignature: string;
    issueDate: string;
    nextUpdate: string;
  }>;
  /** TCB Info JSON for the first (primary) FMSPC — convenience accessor */
  tcbInfoJson: string;
  issueDate: string;
  qeIdentityJson: string;
  qeIdentitySignature: string;
  pckCrlDer: Uint8Array;
  /** Intel Root CA CRL (DER) for checking intermediate cert revocation */
  rootCaCrlDer?: Uint8Array;
  /** PEM chain: PCK CRL issuer → Intel Root CA (from Sgx-PCK-CRL-Issuer-Chain header) */
  pckCrlIssuerChain?: string;
  /** PEM chain: TCB Info signer → Intel Root CA (from Sgx-TCB-Info-Issuer-Chain header) */
  tcbInfoIssuerChain?: string;
  /** PEM chain: QE Identity signer → Intel Root CA (from Sgx-Enclave-Identity-Issuer-Chain header) */
  qeIdentityIssuerChain?: string;
}

const data: CollateralData = {
  entries: ${JSON.stringify(entries, null, 2)},
  tcbInfoJson: ${JSON.stringify(entries[0]?.tcbInfoJson ?? '')},
  issueDate: ${JSON.stringify(entries[0]?.issueDate ?? '')},
  qeIdentityJson: ${JSON.stringify(qeIdentityJson)},
  qeIdentitySignature: ${JSON.stringify(qeIdentitySignature)},
  pckCrlDer: fromHex('${toHex(pckCrlDer)}'),
${rootCaCrlDer ? `  rootCaCrlDer: fromHex('${toHex(rootCaCrlDer)}'),\n` : ''}${pckCrlIssuerChain ? `  pckCrlIssuerChain: ${JSON.stringify(pckCrlIssuerChain)},\n` : ''}${tcbInfoIssuerChain ? `  tcbInfoIssuerChain: ${JSON.stringify(tcbInfoIssuerChain)},\n` : ''}${qeIdentityIssuerChain ? `  qeIdentityIssuerChain: ${JSON.stringify(qeIdentityIssuerChain)},\n` : ''}};

export default data;
`;

  writeFileSync(OUTPUT, output);
  console.log(`\nWrote ${OUTPUT}`);
  console.log(`  ${entries.length} FMSPC(s), PCK CRL ${pckCrlDer.length}B`);
}

main().catch(err => {
  console.error('Failed to fetch collateral:', err);
  process.exit(1);
});
