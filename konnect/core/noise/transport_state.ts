import type { CipherState } from "./cipher_state.ts";

export class TransportState {
  private sendingCipher: CipherState;
  private receivingCipher: CipherState;

  constructor(c1: CipherState, c2: CipherState, initiator: boolean) {
    this.sendingCipher = initiator ? c1 : c2;
    this.receivingCipher = initiator ? c2 : c1;
  }

  async encrypt(plaintext: Uint8Array): Promise<Uint8Array> {
    return this.sendingCipher.encryptWithAd(new Uint8Array(0), plaintext);
  }

  async decrypt(ciphertext: Uint8Array): Promise<Uint8Array> {
    return this.receivingCipher.decryptWithAd(new Uint8Array(0), ciphertext);
  }

  /** Expose for XWing upgrade — replace cipher keys */
  getSendingCipher(): CipherState {
    return this.sendingCipher;
  }

  getReceivingCipher(): CipherState {
    return this.receivingCipher;
  }
}
