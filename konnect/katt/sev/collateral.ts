import { parseAsn1Time, readTL } from "../der.ts";
import type { SevProduct } from "./certs.ts";
import type { SevCollateralData } from "./collateral.generated.ts";

export type { SevCollateralData } from "./collateral.generated.ts";

const DEFAULT_KDS_BASE = "https://kdsintf.amd.com/vcek/v1";

/** CRL date metadata */
export interface CrlMetadata {
  thisUpdate: Date;
  nextUpdate: Date;
}

/**
 * Parse thisUpdate and nextUpdate dates from a DER-encoded CRL.
 *
 * CRL TBSCertList structure:
 *   SEQUENCE {
 *     [version INTEGER]
 *     signature AlgorithmIdentifier
 *     issuer Name
 *     thisUpdate Time
 *     nextUpdate Time
 *     ...
 *   }
 */
export function parseCrlDates(crlDer: Uint8Array): CrlMetadata {
  // Outer SEQUENCE
  const outer = readTL(crlDer, 0);
  if (outer.tag !== 0x30) throw new Error("CRL: expected outer SEQUENCE");

  // TBSCertList SEQUENCE
  let pos = outer.headerSize;
  const tbsTL = readTL(crlDer, pos);
  if (tbsTL.tag !== 0x30) throw new Error("CRL: expected TBSCertList SEQUENCE");

  pos = pos + tbsTL.headerSize;

  // Skip optional version INTEGER (tag 0x02)
  let fieldTL = readTL(crlDer, pos);
  if (fieldTL.tag === 0x02) {
    pos += fieldTL.headerSize + fieldTL.length;
    fieldTL = readTL(crlDer, pos);
  }

  // Skip signature AlgorithmIdentifier (SEQUENCE)
  if (fieldTL.tag !== 0x30) throw new Error("CRL: expected signature algorithm SEQUENCE");
  pos += fieldTL.headerSize + fieldTL.length;

  // Skip issuer Name (SEQUENCE)
  fieldTL = readTL(crlDer, pos);
  if (fieldTL.tag !== 0x30) throw new Error("CRL: expected issuer SEQUENCE");
  pos += fieldTL.headerSize + fieldTL.length;

  // thisUpdate Time
  const thisTL = readTL(crlDer, pos);
  const thisUpdate = parseAsn1Time(
    crlDer.subarray(pos + thisTL.headerSize, pos + thisTL.headerSize + thisTL.length),
    thisTL.tag,
  );
  pos += thisTL.headerSize + thisTL.length;

  // nextUpdate Time
  const nextTL = readTL(crlDer, pos);
  const nextUpdate = parseAsn1Time(
    crlDer.subarray(pos + nextTL.headerSize, pos + nextTL.headerSize + nextTL.length),
    nextTL.tag,
  );

  return { thisUpdate, nextUpdate };
}

/**
 * Fetch live CRL from AMD KDS for a specific product.
 * Requires network access — will not work in browsers (no CORS).
 */
export async function fetchLiveSevCollateral(product: SevProduct, kdsBaseUrl?: string): Promise<SevCollateralData> {
  const KDS_BASE = kdsBaseUrl ?? DEFAULT_KDS_BASE;
  const url = `${KDS_BASE}/${product}/crl`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`AMD KDS CRL: HTTP ${res.status} from ${url}`);
  }
  const crlDer = new Uint8Array(await res.arrayBuffer());

  return {
    crls: { [product]: crlDer },
    fetchedAt: new Date().toISOString(),
  };
}

/**
 * Fetch VCEK certificate from AMD KDS for a specific chip.
 *
 * The reported_tcb is a 64-bit value with SPL bytes at:
 *   byte 0: blSPL, byte 1: teeSPL, byte 6: snpSPL, byte 7: ucodeSPL
 *
 * @param product - AMD product name (Milan, Genoa, Turin)
 * @param chipId - 64-byte chip identifier from the attestation report
 * @param reportedTcb - 64-bit reported TCB value from the attestation report
 * @param kdsBaseUrl - Override AMD KDS base URL
 * @returns VCEK certificate in DER format
 */
export async function fetchVcek(
  product: SevProduct,
  chipId: Uint8Array,
  reportedTcb: bigint,
  kdsBaseUrl?: string,
): Promise<Uint8Array> {
  const KDS_BASE = kdsBaseUrl ?? DEFAULT_KDS_BASE;

  // Extract SPL bytes from the 64-bit TCB value (little-endian)
  const blSPL = Number(reportedTcb & 0xffn);
  const teeSPL = Number((reportedTcb >> 8n) & 0xffn);
  const snpSPL = Number((reportedTcb >> 48n) & 0xffn);
  const ucodeSPL = Number((reportedTcb >> 56n) & 0xffn);

  // Chip ID as hex string
  const chipIdHex = Array.from(chipId)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  const url = `${KDS_BASE}/${product}/${chipIdHex}?blSPL=${blSPL}&teeSPL=${teeSPL}&snpSPL=${snpSPL}&ucodeSPL=${ucodeSPL}`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`AMD KDS VCEK: HTTP ${res.status} from ${url}`);
  }
  return new Uint8Array(await res.arrayBuffer());
}
