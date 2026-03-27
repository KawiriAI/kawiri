import { type CipherKey, noiseCrypto } from "./crypto.ts";

const MAX_NONCE = BigInt("18446744073709551615"); // 2^64 - 1

export class CipherState {
  private k: CipherKey | null = null;
  private n: bigint = 0n;
  private mutex: Promise<void> = Promise.resolve();

  async initializeKey(rawKey: Uint8Array): Promise<void> {
    this.k = await noiseCrypto.importKey(rawKey);
    this.n = 0n;
    this.mutex = Promise.resolve();
  }

  hasKey(): boolean {
    return this.k !== null;
  }

  setNonce(nonce: bigint): void {
    this.n = nonce;
  }

  /** If no key set, returns plaintext unchanged (Noise spec §5.1) */
  async encryptWithAd(ad: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
    if (this.k === null) return plaintext;
    // Serialize through mutex to prevent nonce races
    const prev = this.mutex;
    let release!: () => void;
    this.mutex = new Promise((r) => (release = r));
    await prev;
    try {
      if (this.n >= MAX_NONCE) throw new Error("Nonce overflow");
      const iv = this.formatNonce(this.n);
      const ct = await noiseCrypto.aesGcmEncrypt(this.k, iv, plaintext, ad);
      this.n += 1n;
      return ct;
    } finally {
      release();
    }
  }

  async decryptWithAd(ad: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
    if (this.k === null) return ciphertext;
    const prev = this.mutex;
    let release!: () => void;
    this.mutex = new Promise((r) => (release = r));
    await prev;
    try {
      if (this.n >= MAX_NONCE) throw new Error("Nonce overflow");
      const iv = this.formatNonce(this.n);
      const pt = await noiseCrypto.aesGcmDecrypt(this.k, iv, ciphertext, ad);
      this.n += 1n;
      return pt;
    } finally {
      release();
    }
  }

  private formatNonce(n: bigint): Uint8Array {
    const iv = new Uint8Array(12);
    let value = n;
    for (let i = 11; i >= 4; i--) {
      iv[i] = Number(value & 0xffn);
      value >>= 8n;
    }
    return iv;
  }
}
