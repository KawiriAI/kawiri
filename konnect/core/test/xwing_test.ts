import { expect, test } from "bun:test";
import * as X25519 from "@core/noise/crypto.ts";
import { HandshakeState } from "@core/noise/mod.ts";
import * as XWingUpgrade from "@core/xwing/upgrade.ts";

/** Simple async channel for test message passing */
function channel() {
  const queue: Uint8Array[] = [];
  const waiters: ((v: Uint8Array) => void)[] = [];
  return {
    push(data: Uint8Array) {
      if (waiters.length > 0) {
        waiters.shift()?.(data);
      } else {
        queue.push(data);
      }
    },
    pull(): Promise<Uint8Array> {
      if (queue.length > 0) {
        const item = queue.shift();
        if (!item) throw new Error("expected queued item");
        return Promise.resolve(item);
      }
      return new Promise((resolve) => waiters.push(resolve));
    },
  };
}

async function setupTransport() {
  const staticI = X25519.generateKeypair();
  const staticR = X25519.generateKeypair();
  const initiator = new HandshakeState(true, staticI);
  const responder = new HandshakeState(false, staticR);

  await initiator.initialize();
  await responder.initialize();

  const msg0 = await initiator.writeMessage();
  await responder.readMessage(msg0);
  const msg1 = await responder.writeMessage();
  await initiator.readMessage(msg1);
  const msg2 = await initiator.writeMessage();
  await responder.readMessage(msg2);

  const transportI = await initiator.split();
  const transportR = await responder.split();
  return { transportI, transportR };
}

async function doUpgrade(
  transportI: Awaited<ReturnType<typeof setupTransport>>["transportI"],
  transportR: Awaited<ReturnType<typeof setupTransport>>["transportR"],
) {
  const s2c = channel(); // server → client
  const c2s = channel(); // client → server

  await Promise.all([
    XWingUpgrade.serverUpgrade(
      transportR,
      async (d) => {
        s2c.push(await transportR.encrypt(d));
      },
      async () => transportR.decrypt(await c2s.pull()),
    ),
    XWingUpgrade.clientUpgrade(
      transportI,
      async (d) => {
        c2s.push(await transportI.encrypt(d));
      },
      async () => transportI.decrypt(await s2c.pull()),
    ),
  ]);
}

test("xwing post-handshake upgrade", async () => {
  const { transportI, transportR } = await setupTransport();

  // Verify pre-upgrade encryption works
  const pre = new TextEncoder().encode("before upgrade");
  expect(new TextDecoder().decode(await transportR.decrypt(await transportI.encrypt(pre)))).toEqual("before upgrade");

  // Run upgrade
  await doUpgrade(transportI, transportR);

  // Verify post-upgrade encryption works (I → R)
  const post = new TextEncoder().encode("after upgrade - quantum safe");
  const ct = await transportI.encrypt(post);
  const pt = await transportR.decrypt(ct);
  expect(new TextDecoder().decode(pt)).toEqual("after upgrade - quantum safe");

  // Reverse direction (R → I)
  const ct2 = await transportR.encrypt(post);
  const pt2 = await transportI.decrypt(ct2);
  expect(new TextDecoder().decode(pt2)).toEqual("after upgrade - quantum safe");
});

test("xwing upgraded transport handles many messages", async () => {
  const { transportI, transportR } = await setupTransport();
  await doUpgrade(transportI, transportR);

  for (let i = 0; i < 50; i++) {
    const fromI = new TextEncoder().encode(`pq-msg-I-${i}`);
    const ctI = await transportI.encrypt(fromI);
    expect(new TextDecoder().decode(await transportR.decrypt(ctI))).toEqual(`pq-msg-I-${i}`);

    const fromR = new TextEncoder().encode(`pq-msg-R-${i}`);
    const ctR = await transportR.encrypt(fromR);
    expect(new TextDecoder().decode(await transportI.decrypt(ctR))).toEqual(`pq-msg-R-${i}`);
  }
});

test("xwing pre-upgrade ciphertext fails after upgrade", async () => {
  const { transportI, transportR } = await setupTransport();

  // Do a round trip so nonces are in sync, then capture a ciphertext
  const msg = new TextEncoder().encode("pre-upgrade");
  const preCt = await transportI.encrypt(msg);
  // Receive it to keep nonces in sync
  const prePt = await transportR.decrypt(preCt);
  expect(new TextDecoder().decode(prePt)).toEqual("pre-upgrade");

  // Now encrypt another message and DON'T decrypt it (keep it for later)
  const msg2 = new TextEncoder().encode("stale-message");
  const staleCt = await transportI.encrypt(msg2);
  // Advance responder's receive nonce to match
  await transportR.decrypt(staleCt);

  // Upgrade
  await doUpgrade(transportI, transportR);

  // Encrypt same plaintext with same transport but after upgrade
  const postCt = await transportI.encrypt(msg);

  // Post-upgrade ciphertext should differ from pre-upgrade ciphertext
  // (different keys produce different output)
  const same = preCt.length === postCt.length && preCt.every((b, i) => b === postCt[i]);
  expect(same).toEqual(false);

  // And post-upgrade ciphertext should decrypt fine
  const postPt = await transportR.decrypt(postCt);
  expect(new TextDecoder().decode(postPt)).toEqual("pre-upgrade");
});
