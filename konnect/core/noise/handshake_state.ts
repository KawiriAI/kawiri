import type { Keypair } from "./crypto.ts";
import * as X25519 from "./crypto.ts";
import { SymmetricState } from "./symmetric_state.ts";
import { TransportState } from "./transport_state.ts";

const PROTOCOL_NAME = "Noise_XX_25519_AESGCM_SHA256";
const DH_KEY_SIZE = 32;
const ENCRYPTED_KEY_SIZE = 48; // 32-byte key + 16-byte AES-GCM tag

/**
 * Noise XX three-message handshake:
 *   → e                     msg 0: initiator sends ephemeral pubkey
 *   ← e, ee, s, es          msg 1: responder sends ephemeral + static + attestation
 *   → s, se                 msg 2: initiator sends static
 */
export class HandshakeState {
  private ss = new SymmetricState();
  private e: Keypair | null = null;
  private re: Uint8Array | null = null; // remote ephemeral
  private rs: Uint8Array | null = null; // remote static
  private messageIndex = 0;
  private finished = false;

  constructor(
    private initiator: boolean,
    private s: Keypair,
    rs?: Uint8Array,
    private preE?: Keypair, // for deterministic testing
  ) {
    if (rs) this.rs = rs;
  }

  async initialize(prologue?: Uint8Array): Promise<void> {
    await this.ss.initialize(PROTOCOL_NAME);
    if (prologue) {
      await this.ss.mixHash(prologue);
    } else {
      await this.ss.mixHash(new Uint8Array(0));
    }
  }

  isHandshakeFinished(): boolean {
    return this.finished;
  }

  getRemoteStatic(): Uint8Array | null {
    return this.rs ? new Uint8Array(this.rs) : null;
  }

  getHandshakeHash(): Uint8Array {
    return this.ss.getHandshakeHash();
  }

  getChainingKey(): Uint8Array {
    return this.ss.getChainingKey();
  }

  async writeMessage(payload?: Uint8Array): Promise<Uint8Array> {
    const p = payload ?? new Uint8Array(0);

    if (this.initiator) {
      if (this.messageIndex === 0) {
        return this.writeMsg0(p);
      } else if (this.messageIndex === 2) {
        return this.writeMsg2(p);
      }
    } else {
      if (this.messageIndex === 1) {
        return this.writeMsg1(p);
      }
    }
    throw new Error(`Invalid write at messageIndex=${this.messageIndex} initiator=${this.initiator}`);
  }

  async readMessage(message: Uint8Array): Promise<Uint8Array> {
    if (this.initiator) {
      if (this.messageIndex === 1) {
        return this.readMsg1(message);
      }
    } else {
      if (this.messageIndex === 0) {
        return this.readMsg0(message);
      } else if (this.messageIndex === 2) {
        return this.readMsg2(message);
      }
    }
    throw new Error(`Invalid read at messageIndex=${this.messageIndex} initiator=${this.initiator}`);
  }

  async split(): Promise<TransportState> {
    if (!this.finished) throw new Error("Handshake not finished");
    const [c1, c2] = await this.ss.split();
    return new TransportState(c1, c2, this.initiator);
  }

  // --- Message 0: → e ---
  private async writeMsg0(payload: Uint8Array): Promise<Uint8Array> {
    this.e = this.preE ?? X25519.generateKeypair();
    await this.ss.mixHash(this.e.publicKey);
    const encPayload = await this.ss.encryptAndMixHash(payload);

    const msg = new Uint8Array(DH_KEY_SIZE + encPayload.length);
    msg.set(this.e.publicKey, 0);
    msg.set(encPayload, DH_KEY_SIZE);

    this.messageIndex = 1; // next expected: read msg 1
    return msg;
  }

  private async readMsg0(message: Uint8Array): Promise<Uint8Array> {
    this.re = message.slice(0, DH_KEY_SIZE);
    await this.ss.mixHash(this.re);
    const payload = await this.ss.decryptAndMixHash(message.slice(DH_KEY_SIZE));

    this.messageIndex = 1; // next expected: write msg 1
    return payload;
  }

  // --- Message 1: ← e, ee, s, es ---
  private async writeMsg1(payload: Uint8Array): Promise<Uint8Array> {
    this.e = this.preE ?? X25519.generateKeypair();

    // e
    await this.ss.mixHash(this.e.publicKey);

    // ee
    if (!this.re) throw new Error("Remote ephemeral key not set");
    const dhEE = X25519.dh(this.e.privateKey, this.re);
    await this.ss.mixKey(dhEE);

    // s (encrypted)
    const encS = await this.ss.encryptAndMixHash(this.s.publicKey);

    // es: responder's static, initiator's ephemeral
    const dhES = X25519.dh(this.s.privateKey, this.re);
    await this.ss.mixKey(dhES);

    // payload (encrypted)
    const encPayload = await this.ss.encryptAndMixHash(payload);

    const msg = new Uint8Array(DH_KEY_SIZE + encS.length + encPayload.length);
    msg.set(this.e.publicKey, 0);
    msg.set(encS, DH_KEY_SIZE);
    msg.set(encPayload, DH_KEY_SIZE + encS.length);

    this.messageIndex = 2; // next expected: read msg 2
    return msg;
  }

  private async readMsg1(message: Uint8Array): Promise<Uint8Array> {
    let offset = 0;

    // e
    this.re = message.slice(offset, offset + DH_KEY_SIZE);
    offset += DH_KEY_SIZE;
    await this.ss.mixHash(this.re);

    // ee
    if (!this.e) throw new Error("Local ephemeral keypair not set");
    const dhEE = X25519.dh(this.e.privateKey, this.re);
    await this.ss.mixKey(dhEE);

    // s (encrypted — 32 + 16 tag)
    const encS = message.slice(offset, offset + ENCRYPTED_KEY_SIZE);
    offset += ENCRYPTED_KEY_SIZE;
    const remoteStatic = await this.ss.decryptAndMixHash(encS);
    this.rs = remoteStatic;

    // es: responder's static, initiator's ephemeral
    const dhES = X25519.dh(this.e.privateKey, this.rs);
    await this.ss.mixKey(dhES);

    // payload (encrypted)
    const payload = await this.ss.decryptAndMixHash(message.slice(offset));

    this.messageIndex = 2; // next expected: write msg 2
    return payload;
  }

  // --- Message 2: → s, se ---
  private async writeMsg2(payload: Uint8Array): Promise<Uint8Array> {
    // s (encrypted)
    const encS = await this.ss.encryptAndMixHash(this.s.publicKey);

    // se: initiator's static, responder's ephemeral
    if (!this.re) throw new Error("Remote ephemeral key not set");
    const dhSE = X25519.dh(this.s.privateKey, this.re);
    await this.ss.mixKey(dhSE);

    // payload (encrypted)
    const encPayload = await this.ss.encryptAndMixHash(payload);

    const msg = new Uint8Array(encS.length + encPayload.length);
    msg.set(encS, 0);
    msg.set(encPayload, encS.length);

    this.messageIndex = 3;
    this.finished = true;
    return msg;
  }

  private async readMsg2(message: Uint8Array): Promise<Uint8Array> {
    let offset = 0;

    // s (encrypted — 32 + 16 tag)
    const encS = message.slice(offset, offset + ENCRYPTED_KEY_SIZE);
    offset += ENCRYPTED_KEY_SIZE;
    const remoteStatic = await this.ss.decryptAndMixHash(encS);
    this.rs = remoteStatic;

    // se: initiator's static, responder's ephemeral
    if (!this.e) throw new Error("Local ephemeral keypair not set");
    const dhSE = X25519.dh(this.e.privateKey, this.rs);
    await this.ss.mixKey(dhSE);

    // payload (encrypted)
    const payload = await this.ss.decryptAndMixHash(message.slice(offset));

    this.messageIndex = 3;
    this.finished = true;
    return payload;
  }
}
