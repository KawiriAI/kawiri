import { XWing } from "@noble/post-quantum/hybrid.js";
import type { TransportState } from "../noise/transport_state.ts";

const PQ_INFO = new TextEncoder().encode("transport");
const PQ_SALT = new TextEncoder().encode("pq-upgrade-v1");

/** Message types for the upgrade protocol */
interface UpgradeMsg1 {
  type: "pq-upgrade";
  publicKey: string; // base64
}
interface UpgradeMsg2 {
  type: "pq-upgrade-reply";
  cipherText: string; // base64
}

/**
 * Server side: generate keypair, send public key, wait for ciphertext,
 * derive new keys and replace transport ciphers.
 */
export async function serverUpgrade(
  transport: TransportState,
  send: (data: Uint8Array) => Promise<void>,
  receive: () => Promise<Uint8Array>,
): Promise<void> {
  const keys = XWing.keygen();

  const msg1: UpgradeMsg1 = {
    type: "pq-upgrade",
    publicKey: encodeBase64(keys.publicKey),
  };
  await send(new TextEncoder().encode(JSON.stringify(msg1)));

  const raw = await receive();
  const msg2: UpgradeMsg2 = JSON.parse(new TextDecoder().decode(raw));
  if (msg2.type !== "pq-upgrade-reply") throw new Error("unexpected upgrade message");

  const cipherText = decodeBase64(msg2.cipherText);
  const sharedSecret = XWing.decapsulate(cipherText, keys.secretKey);

  await replaceKeys(transport, sharedSecret, false);
}

/**
 * Client side: receive public key, encapsulate, send ciphertext,
 * derive new keys and replace transport ciphers.
 */
export async function clientUpgrade(
  transport: TransportState,
  send: (data: Uint8Array) => Promise<void>,
  receive: () => Promise<Uint8Array>,
): Promise<void> {
  const raw = await receive();
  const msg1: UpgradeMsg1 = JSON.parse(new TextDecoder().decode(raw));
  if (msg1.type !== "pq-upgrade") throw new Error("unexpected upgrade message");

  const publicKey = decodeBase64(msg1.publicKey);
  const { cipherText, sharedSecret } = XWing.encapsulate(publicKey);

  const msg2: UpgradeMsg2 = {
    type: "pq-upgrade-reply",
    cipherText: encodeBase64(cipherText),
  };
  await send(new TextEncoder().encode(JSON.stringify(msg2)));

  await replaceKeys(transport, sharedSecret, true);
}

async function replaceKeys(transport: TransportState, kemSecret: Uint8Array, isInitiator: boolean): Promise<void> {
  // HKDF to derive 2 new 32-byte keys from the KEM secret
  const baseKey = await crypto.subtle.importKey(
    "raw",
    kemSecret.buffer.slice(kemSecret.byteOffset, kemSecret.byteOffset + kemSecret.byteLength) as ArrayBuffer,
    { name: "HKDF" },
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: PQ_SALT, info: PQ_INFO },
    baseKey,
    64 * 8, // 64 bytes = 2 keys
  );
  const all = new Uint8Array(bits);
  const newKey1 = all.slice(0, 32);
  const newKey2 = all.slice(32, 64);

  // Initiator: send with key1, receive with key2
  // Responder: send with key2, receive with key1
  if (isInitiator) {
    await transport.getSendingCipher().initializeKey(newKey1);
    await transport.getReceivingCipher().initializeKey(newKey2);
  } else {
    await transport.getSendingCipher().initializeKey(newKey2);
    await transport.getReceivingCipher().initializeKey(newKey1);
  }
}

function encodeBase64(data: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < data.length; i++) binary += String.fromCharCode(data[i]);
  return btoa(binary);
}

function decodeBase64(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}
