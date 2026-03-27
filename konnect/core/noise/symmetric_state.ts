import { CipherState } from "./cipher_state.ts";
import { noiseCrypto } from "./crypto.ts";

export class SymmetricState {
  private cs = new CipherState();
  private ck = new Uint8Array(32);
  private h = new Uint8Array(32);

  /** Protocol name → initial h and ck. If name fits in 32 bytes, pad with zeros; else hash. */
  async initialize(protocolName: string): Promise<void> {
    const encoded = new TextEncoder().encode(protocolName);
    if (encoded.length <= 32) {
      this.h = new Uint8Array(32);
      this.h.set(encoded);
    } else {
      const hashed = await noiseCrypto.sha256(encoded);
      this.h = new Uint8Array(hashed);
    }
    this.ck = new Uint8Array(this.h);
  }

  getHandshakeHash(): Uint8Array {
    return new Uint8Array(this.h);
  }

  getChainingKey(): Uint8Array {
    return new Uint8Array(this.ck);
  }

  hasKey(): boolean {
    return this.cs.hasKey();
  }

  /** h = SHA-256(h || data) */
  async mixHash(data: Uint8Array): Promise<void> {
    const combined = new Uint8Array(this.h.length + data.length);
    combined.set(this.h);
    combined.set(data, this.h.length);
    const hashed = await noiseCrypto.sha256(combined);
    this.h = new Uint8Array(hashed);
  }

  /** ck, tempK = HKDF(ck, ikm, 2); cs.InitializeKey(tempK) */
  async mixKey(inputKeyMaterial: Uint8Array): Promise<void> {
    const [newCk, tempK] = await noiseCrypto.hkdf(this.ck, inputKeyMaterial, 2);
    this.ck = new Uint8Array(newCk);
    await this.cs.initializeKey(tempK);
  }

  /** Encrypt (if key set) then mixHash the output */
  async encryptAndMixHash(plaintext: Uint8Array): Promise<Uint8Array> {
    if (this.cs.hasKey()) {
      const ciphertext = await this.cs.encryptWithAd(this.h, plaintext);
      await this.mixHash(ciphertext);
      return ciphertext;
    }
    await this.mixHash(plaintext);
    return plaintext;
  }

  /** Always mixHash the ciphertext (not plaintext!) */
  async decryptAndMixHash(ciphertext: Uint8Array): Promise<Uint8Array> {
    if (this.cs.hasKey()) {
      const plaintext = await this.cs.decryptWithAd(this.h, ciphertext);
      await this.mixHash(ciphertext);
      return plaintext;
    }
    await this.mixHash(ciphertext);
    return ciphertext;
  }

  /** Derive two CipherStates for transport: [initiator→responder, responder→initiator] */
  async split(): Promise<[CipherState, CipherState]> {
    const [k1, k2] = await noiseCrypto.hkdf(this.ck, new Uint8Array(0), 2);
    const c1 = new CipherState();
    const c2 = new CipherState();
    await c1.initializeKey(k1);
    await c2.initializeKey(k2);
    return [c1, c2];
  }
}
