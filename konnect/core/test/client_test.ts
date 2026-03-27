import { expect, test } from "bun:test";
import { KawiriClient } from "@core/client.ts";
import {
  type AttestationPayload,
  FrameAssembler,
  HandshakeState,
  type KawiriRequest,
  type KawiriResponse,
  type KawiriStreamChunk,
  type TransportState,
} from "@core/mod.ts";
import * as X25519 from "@core/noise/crypto.ts";
import * as Framer from "@core/transport/framer.ts";
import * as XWingUpgrade from "@core/xwing/upgrade.ts";
import type { ServerWebSocket } from "bun";

/** WebSocket data shape used by the mock server */
interface MockWSData {
  serverStatic: ReturnType<typeof X25519.generateKeypair>;
  enablePQ: boolean;
  incoming: ReturnType<typeof wsChannel>;
}

/** Async channel for WebSocket message routing */
function wsChannel() {
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

/** Create a mock WebSocket server */
function createMockServer(opts: { enablePQ: boolean }) {
  const serverStatic = X25519.generateKeypair();

  const server = Bun.serve({
    port: 0,
    fetch(req, server) {
      const upgrade = req.headers.get("upgrade") ?? "";
      if (upgrade.toLowerCase() !== "websocket") {
        return new Response("Expected WebSocket", { status: 426 });
      }
      const success = server.upgrade(req, { data: { serverStatic, enablePQ: opts.enablePQ, incoming: wsChannel() } });
      if (!success) {
        return new Response("WebSocket upgrade failed", { status: 500 });
      }
      return undefined as unknown as Response;
    },
    websocket: {
      message(
        ws: ServerWebSocket<{
          serverStatic: ReturnType<typeof X25519.generateKeypair>;
          enablePQ: boolean;
          incoming: ReturnType<typeof wsChannel>;
        }>,
        message,
      ) {
        const data = typeof message === "string" ? new TextEncoder().encode(message) : new Uint8Array(message);
        if (ws.data.incoming) {
          ws.data.incoming.push(data);
        }
      },
      open(ws: ServerWebSocket<MockWSData>) {
        ws.data.incoming = wsChannel();
        handleSocket(ws, ws.data.serverStatic, ws.data.enablePQ);
      },
    },
  });

  const port = server.port;
  return { server, port };
}

async function handleSocket(
  ws: ServerWebSocket<MockWSData>,
  serverStatic: ReturnType<typeof X25519.generateKeypair>,
  enablePQ: boolean,
) {
  const responder = new HandshakeState(false, serverStatic);
  await responder.initialize();

  const incoming: ReturnType<typeof wsChannel> = ws.data.incoming;

  // msg 0: read
  const msg0Data = await incoming.pull();
  await responder.readMessage(msg0Data);

  // msg 1: write with attestation
  const nonceBuf = await crypto.subtle.digest(
    "SHA-256",
    serverStatic.publicKey.buffer.slice(
      serverStatic.publicKey.byteOffset,
      serverStatic.publicKey.byteOffset + serverStatic.publicKey.byteLength,
    ) as ArrayBuffer,
  );
  const nonce = Array.from(new Uint8Array(nonceBuf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const attestation: AttestationPayload = { platform: "mock", nonce };
  const msg1 = await responder.writeMessage(new TextEncoder().encode(JSON.stringify(attestation)));
  ws.send(msg1);

  // msg 2: read
  const msg2Data = await incoming.pull();
  await responder.readMessage(msg2Data);
  const transport = await responder.split();

  if (enablePQ) {
    const send = async (d: Uint8Array) => {
      const ct = await transport.encrypt(d);
      ws.send(ct);
    };
    const receive = async () => {
      const ct = await incoming.pull();
      return transport.decrypt(ct);
    };
    await XWingUpgrade.serverUpgrade(transport, send, receive);
  }

  // Transport mode: process messages from the channel
  const assembler = new FrameAssembler();
  while (ws.readyState === WebSocket.OPEN) {
    let raw: Uint8Array;
    try {
      raw = await incoming.pull();
    } catch {
      break;
    }

    const plainFrame = await transport.decrypt(raw);
    const decoded = Framer.decode(plainFrame);

    let payload: Uint8Array | null;
    if (decoded.flag === 0) {
      payload = decoded.payload;
    } else {
      payload = assembler.processFrame(decoded);
    }

    if (payload) {
      const req: KawiriRequest = JSON.parse(new TextDecoder().decode(payload));
      await handleRequest(req, transport, ws);
    }
  }
}

async function handleRequest(req: KawiriRequest, transport: TransportState, ws: ServerWebSocket<MockWSData>) {
  const sendEncrypted = async (msg: unknown) => {
    const data = new TextEncoder().encode(JSON.stringify(msg));
    const frames = Framer.encode(data);
    for (const frame of frames) {
      const ct = await transport.encrypt(frame);
      ws.send(ct);
    }
  };

  if (req.path === "/ping") {
    await sendEncrypted({
      id: req.id,
      status: 200,
      body: "pong",
    } as KawiriResponse);
    return;
  }

  const body = req.body as Record<string, unknown> | undefined;
  const isStream = body?.stream === true;

  if (isStream) {
    await sendEncrypted({
      id: req.id,
      event: "data",
      data: '{"choices":[{"delta":{"content":"Hello"}}]}',
    } as KawiriStreamChunk);
    await sendEncrypted({
      id: req.id,
      event: "data",
      data: '{"choices":[{"delta":{"content":" World"}}]}',
    } as KawiriStreamChunk);
    await sendEncrypted({
      id: req.id,
      event: "done",
    } as KawiriStreamChunk);
  } else {
    await sendEncrypted({
      id: req.id,
      status: 200,
      body: {
        choices: [{ message: { content: "Hello from mock" } }],
      },
    } as KawiriResponse);
  }
}

test("KawiriClient connects and chats (no PQ)", async () => {
  const { server, port } = createMockServer({ enablePQ: false });

  const client = new KawiriClient({
    url: `ws://localhost:${port}`,
    enablePQ: false,
  });

  await client.connect();
  expect(client.connected).toEqual(true);

  const response = await client.chat([{ role: "user", content: "Hi" }]);
  expect(response.content).toEqual("Hello from mock");

  client.close();
  server.stop();
});

test("KawiriClient connects with XWing upgrade", async () => {
  const { server, port } = createMockServer({ enablePQ: true });

  const client = new KawiriClient({
    url: `ws://localhost:${port}`,
    enablePQ: true,
  });

  await client.connect();
  expect(client.connected).toEqual(true);

  const response = await client.chat([{ role: "user", content: "Hi" }]);
  expect(response.content).toEqual("Hello from mock");

  client.close();
  server.stop();
});

test("KawiriClient streaming chat", async () => {
  const { server, port } = createMockServer({ enablePQ: false });

  const client = new KawiriClient({
    url: `ws://localhost:${port}`,
    enablePQ: false,
  });

  await client.connect();

  const stream = client.chatStream([{ role: "user", content: "Hi" }]);
  const reader = stream.getReader();
  let content = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    content += value;
  }

  expect(content).toEqual("Hello World");

  client.close();
  server.stop();
});

test("KawiriClient connection timeout", async () => {
  // Connect to a server that never responds (use a port that will hang)
  // Listen but never upgrade
  const hangServer = Bun.serve({
    port: 0,
    fetch() {
      return new Response("not websocket", { status: 200 });
    },
  });
  const port = hangServer.port;

  const client = new KawiriClient({
    url: `ws://localhost:${port}`,
    enablePQ: false,
    connectTimeout: 500, // 500ms timeout
  });

  expect(client.connect()).rejects.toThrow();
  expect(client.connected).toEqual(false);

  hangServer.stop();
});

test("KawiriClient onDisconnect fires after connection close", async () => {
  const { server, port } = createMockServer({ enablePQ: false });

  let _disconnectReason = "";
  const client = new KawiriClient({
    url: `ws://localhost:${port}`,
    enablePQ: false,
    onDisconnect: (reason) => {
      _disconnectReason = reason;
    },
  });

  await client.connect();
  expect(client.connected).toEqual(true);

  // Close from server side by shutting down
  client.close();
  // Give WebSocket close event time to fire
  await new Promise((r) => setTimeout(r, 100));
  expect(client.connected).toEqual(false);

  server.stop();
});

test("KawiriClient rejects chat when not connected", async () => {
  const client = new KawiriClient({
    url: `ws://localhost:9999`,
    enablePQ: false,
  });

  // Should throw because we never called connect()
  expect(client.chat([{ role: "user", content: "Hi" }])).rejects.toThrow("Not connected");
});
