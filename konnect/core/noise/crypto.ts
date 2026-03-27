import { x25519 } from "@noble/curves/ed25519";
import { randomBytes } from "@noble/hashes/utils";

export interface Keypair {
  privateKey: Uint8Array; // 32 bytes
  publicKey: Uint8Array; // 32 bytes
}

/** Wraps two CryptoKey handles (encrypt + decrypt). WebCrypto requires separate key objects. */
export class CipherKey {
  constructor(
    public readonly encryptKey: CryptoKey,
    public readonly decryptKey: CryptoKey,
  ) {}
}

/** Convert Uint8Array to ArrayBuffer for WebCrypto APIs */
function toBuffer(data: Uint8Array): ArrayBuffer {
  return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
}

/** X25519 helpers */
export function generateKeypair(): Keypair {
  const privateKey = randomBytes(32);
  const publicKey = x25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

export function dh(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  return x25519.getSharedSecret(privateKey, publicKey);
}

/** All symmetric operations via WebCrypto */
class NoiseCrypto {
  async sha256(data: Uint8Array): Promise<Uint8Array> {
    const digest = await crypto.subtle.digest("SHA-256", toBuffer(data));
    return new Uint8Array(digest);
  }

  async importKey(rawKey: Uint8Array): Promise<CipherKey> {
    const buf = toBuffer(rawKey);
    const encryptKey = await crypto.subtle.importKey("raw", buf, { name: "AES-GCM" }, false, ["encrypt"]);
    const decryptKey = await crypto.subtle.importKey("raw", buf, { name: "AES-GCM" }, false, ["decrypt"]);
    return new CipherKey(encryptKey, decryptKey);
  }

  async aesGcmEncrypt(key: CipherKey, iv: Uint8Array, plaintext: Uint8Array, ad: Uint8Array): Promise<Uint8Array> {
    const ct = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: toBuffer(iv),
        additionalData: toBuffer(ad),
        tagLength: 128,
      },
      key.encryptKey,
      toBuffer(plaintext),
    );
    return new Uint8Array(ct);
  }

  async aesGcmDecrypt(key: CipherKey, iv: Uint8Array, ciphertext: Uint8Array, ad: Uint8Array): Promise<Uint8Array> {
    const pt = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: toBuffer(iv),
        additionalData: toBuffer(ad),
        tagLength: 128,
      },
      key.decryptKey,
      toBuffer(ciphertext),
    );
    return new Uint8Array(pt);
  }

  /** HKDF-SHA256 via manual HMAC (handles empty ikm per Noise spec). */
  async hkdf(salt: Uint8Array, ikm: Uint8Array, numOutputs: number): Promise<Uint8Array[]> {
    // HKDF-Extract: PRK = HMAC-SHA256(salt, ikm)
    const saltKey = await crypto.subtle.importKey("raw", toBuffer(salt), { name: "HMAC", hash: "SHA-256" }, false, [
      "sign",
    ]);
    const prk = new Uint8Array(await crypto.subtle.sign("HMAC", saltKey, toBuffer(ikm)));

    // HKDF-Expand: generate numOutputs * 32 bytes
    const outputs: Uint8Array[] = [];
    let prev = new Uint8Array(0);
    const prkKey = await crypto.subtle.importKey("raw", toBuffer(prk), { name: "HMAC", hash: "SHA-256" }, false, [
      "sign",
    ]);

    for (let i = 1; i <= numOutputs; i++) {
      const input = new Uint8Array(prev.length + 1);
      input.set(prev);
      input[prev.length] = i;
      prev = new Uint8Array(await crypto.subtle.sign("HMAC", prkKey, toBuffer(input)));
      outputs.push(prev);
    }

    return outputs;
  }
}

export const noiseCrypto = new NoiseCrypto();
