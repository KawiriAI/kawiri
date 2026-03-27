/**
 * TypeScript 5.7+ made Uint8Array generic: Uint8Array<ArrayBufferLike>.
 * WebCrypto's BufferSource expects ArrayBufferView<ArrayBuffer>, creating a mismatch.
 * These overloads let SubtleCrypto accept Uint8Array directly.
 */
declare global {
  interface SubtleCrypto {
    importKey(
      format: "raw" | "pkcs8" | "spki",
      keyData: Uint8Array,
      algorithm: AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams | HmacImportParams,
      extractable: boolean,
      keyUsages: KeyUsage[],
    ): Promise<CryptoKey>;
    verify(
      algorithm: AlgorithmIdentifier | RsaPssParams | EcdsaParams,
      key: CryptoKey,
      signature: Uint8Array,
      data: Uint8Array,
    ): Promise<boolean>;
    digest(algorithm: AlgorithmIdentifier, data: Uint8Array): Promise<ArrayBuffer>;
    sign(
      algorithm: AlgorithmIdentifier | RsaPssParams | EcdsaParams,
      key: CryptoKey,
      data: Uint8Array,
    ): Promise<ArrayBuffer>;
  }
}

const HEX_CHARS = "0123456789abcdef";

/** Encode a Uint8Array to a lowercase hex string */
export function toHex(bytes: Uint8Array): string {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += HEX_CHARS[bytes[i] >> 4] + HEX_CHARS[bytes[i] & 0x0f];
  }
  return hex;
}

/** Decode a hex string to a Uint8Array */
export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error("Hex string must have even length");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    const hi = parseInt(hex[i * 2], 16);
    const lo = parseInt(hex[i * 2 + 1], 16);
    if (Number.isNaN(hi) || Number.isNaN(lo)) {
      throw new Error(`Invalid hex character at position ${i * 2}`);
    }
    bytes[i] = (hi << 4) | lo;
  }
  return bytes;
}

/** Constant-time comparison of two byte arrays. Returns true if equal. */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/** Reverse the bytes in an array (for AMD little-endian to big-endian conversion) */
export function reverseBytes(bytes: Uint8Array): Uint8Array {
  const result = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    result[i] = bytes[bytes.length - 1 - i];
  }
  return result;
}

/** Convert a big-endian byte array to a BigInt */
export function bytesToBigInt(bytes: Uint8Array): bigint {
  if (bytes.length === 0) return 0n;
  let result = 0n;
  for (const byte of bytes) {
    result = (result << 8n) | BigInt(byte);
  }
  return result;
}

/** Compare two serial numbers, normalizing leading zeros */
export function serialsEqual(a: Uint8Array, b: Uint8Array): boolean {
  let ai = 0;
  while (ai < a.length - 1 && a[ai] === 0) ai++;
  let bi = 0;
  while (bi < b.length - 1 && b[bi] === 0) bi++;

  const aStripped = a.subarray(ai);
  const bStripped = b.subarray(bi);

  if (aStripped.length !== bStripped.length) return false;
  for (let i = 0; i < aStripped.length; i++) {
    if (aStripped[i] !== bStripped[i]) return false;
  }
  return true;
}

/** Simple byte array equality check (non-constant-time, for non-security-sensitive comparisons like OIDs) */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/** Decode a base64 string to a Uint8Array */
export function b64Decode(s: string): Uint8Array {
  const binary = atob(s);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Encode a Uint8Array to a base64 string */
export function b64Encode(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

/** Convert a BigInt to a fixed-size big-endian byte array, zero-padded */
export function bigIntToBytes(value: bigint, size: number): Uint8Array {
  if (value < 0n) throw new Error("bigIntToBytes: negative value");
  if (value >> BigInt(size * 8) > 0n) {
    throw new Error(`bigIntToBytes: value requires more than ${size} bytes`);
  }
  const result = new Uint8Array(size);
  let v = value;
  for (let i = size - 1; i >= 0; i--) {
    result[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return result;
}
