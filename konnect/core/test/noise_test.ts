import { expect, test } from "bun:test";
import * as X25519 from "@core/noise/crypto.ts";
import { HandshakeState } from "@core/noise/mod.ts";

async function doHandshake(attestation?: Uint8Array) {
  const staticI = X25519.generateKeypair();
  const staticR = X25519.generateKeypair();

  const initiator = new HandshakeState(true, staticI);
  const responder = new HandshakeState(false, staticR);

  await initiator.initialize();
  await responder.initialize();

  // msg 0: I → R
  const msg0 = await initiator.writeMessage();
  const payload0 = await responder.readMessage(msg0);

  // msg 1: R → I (with optional attestation payload)
  const msg1 = await responder.writeMessage(attestation);
  const payload1 = await initiator.readMessage(msg1);

  // msg 2: I → R
  const msg2 = await initiator.writeMessage();
  const payload2 = await responder.readMessage(msg2);

  return { initiator, responder, staticI, staticR, payload0, payload1, payload2 };
}

test("noise XX handshake completes", async () => {
  const staticI = X25519.generateKeypair();
  const staticR = X25519.generateKeypair();

  const initiator = new HandshakeState(true, staticI);
  const responder = new HandshakeState(false, staticR);

  await initiator.initialize();
  await responder.initialize();

  // msg 0: I → R
  const msg0 = await initiator.writeMessage();
  const payload0 = await responder.readMessage(msg0);
  expect(payload0.length).toEqual(0);

  // msg 1: R → I (with attestation payload)
  const attestation = new TextEncoder().encode('{"platform":"mock"}');
  const msg1 = await responder.writeMessage(attestation);
  const payload1 = await initiator.readMessage(msg1);
  expect(new TextDecoder().decode(payload1)).toEqual('{"platform":"mock"}');

  // msg 2: I → R
  const msg2 = await initiator.writeMessage();
  await responder.readMessage(msg2);

  // Both should be finished
  expect(initiator.isHandshakeFinished()).toEqual(true);
  expect(responder.isHandshakeFinished()).toEqual(true);

  // Remote static keys should match
  expect(initiator.getRemoteStatic()).toEqual(staticR.publicKey);
  expect(responder.getRemoteStatic()).toEqual(staticI.publicKey);
});

test("noise transport encrypt/decrypt", async () => {
  const { initiator, responder } = await doHandshake();

  const transportI = await initiator.split();
  const transportR = await responder.split();

  // I → R
  const message = new TextEncoder().encode("hello from initiator");
  const ct = await transportI.encrypt(message);
  const pt = await transportR.decrypt(ct);
  expect(new TextDecoder().decode(pt)).toEqual("hello from initiator");

  // R → I
  const reply = new TextEncoder().encode("hello from responder");
  const ct2 = await transportR.encrypt(reply);
  const pt2 = await transportI.decrypt(ct2);
  expect(new TextDecoder().decode(pt2)).toEqual("hello from responder");
});

test("noise transport handles multiple messages", async () => {
  const { initiator, responder } = await doHandshake();
  const transportI = await initiator.split();
  const transportR = await responder.split();

  for (let i = 0; i < 100; i++) {
    const msg = new TextEncoder().encode(`message ${i}`);
    const ct = await transportI.encrypt(msg);
    const pt = await transportR.decrypt(ct);
    expect(new TextDecoder().decode(pt)).toEqual(`message ${i}`);
  }
});

test("noise transport rejects tampered ciphertext", async () => {
  const { initiator, responder } = await doHandshake();
  const transportI = await initiator.split();
  const transportR = await responder.split();

  const ct = await transportI.encrypt(new TextEncoder().encode("secret"));
  // Flip a byte
  ct[10] ^= 0xff;
  expect(transportR.decrypt(ct)).rejects.toThrow();
});

test("noise handshake carries large payload", async () => {
  // Test that attestation payloads of various sizes work
  const largePayload = new TextEncoder().encode(
    JSON.stringify({
      platform: "TDX",
      quote: "A".repeat(4096),
      nonce: "deadbeef".repeat(8),
    }),
  );
  const { payload1 } = await doHandshake(largePayload);
  const parsed = JSON.parse(new TextDecoder().decode(payload1));
  expect(parsed.platform).toEqual("TDX");
  expect(parsed.quote.length).toEqual(4096);
});

test("noise handshake hash is identical on both sides", async () => {
  const { initiator, responder } = await doHandshake();
  expect(initiator.getHandshakeHash()).toEqual(responder.getHandshakeHash());
});

test("noise bidirectional transport interleaved", async () => {
  const { initiator, responder } = await doHandshake();
  const transportI = await initiator.split();
  const transportR = await responder.split();

  // Interleaved: I sends, R sends, I sends, R sends
  for (let i = 0; i < 50; i++) {
    const fromI = new TextEncoder().encode(`I→R #${i}`);
    const ctI = await transportI.encrypt(fromI);
    expect(new TextDecoder().decode(await transportR.decrypt(ctI))).toEqual(`I→R #${i}`);

    const fromR = new TextEncoder().encode(`R→I #${i}`);
    const ctR = await transportR.encrypt(fromR);
    expect(new TextDecoder().decode(await transportI.decrypt(ctR))).toEqual(`R→I #${i}`);
  }
});
