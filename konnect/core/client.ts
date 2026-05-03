import { type AttestationValidator, StubValidator } from "./attestation/validator.ts";
import * as X25519 from "./noise/crypto.ts";
import { HandshakeState, type TransportState } from "./noise/mod.ts";
import * as Framer from "./transport/framer.ts";
import { FrameAssembler } from "./transport/framer.ts";
import type {
  AttestationPayload,
  ChatMessage,
  ChatOptions,
  ChatResult,
  KawiriRequest,
  KawiriResponse,
  KawiriStreamChunk,
} from "./transport/types.ts";
import * as XWingUpgrade from "./xwing/upgrade.ts";

/** Timing breakdown of the connect() handshake (ms). */
export interface ConnectTiming {
  wsOpen: number; // WebSocket open
  noiseMsg1: number; // read msg1 (includes server-side attestation generation)
  validation: number; // client-side attestation verification
  noiseMsg2: number; // write msg2 + split
  xwingUpgrade: number; // post-quantum key exchange (0 if enablePQ=false)
  total: number;
}

export interface KawiriClientOptions {
  url: string; // ws:// or wss://
  validator?: AttestationValidator;
  enablePQ?: boolean; // default: true (XWing upgrade)
  connectTimeout?: number; // default: 10000 (10s)
  debug?: boolean; // default: false — log handshake timing via console.debug
  onDisconnect?: (reason: string) => void;
}

interface PendingRequest {
  resolve: (value: ChatResult) => void;
  reject: (err: Error) => void;
  stream?: ReadableStreamDefaultController<string>;
}

export class KawiriClient {
  private ws: WebSocket | null = null;
  private transport: TransportState | null = null;
  private assembler = new FrameAssembler();
  private pending = new Map<number, PendingRequest>();
  private nextId = 1;
  private options: Required<KawiriClientOptions>;
  private _connected = false;
  private _timing: ConnectTiming | null = null;
  /**
   * True when the validator accepted a `platform: "mock"` attestation.
   * Drives the per-message warnings — every send and every recv emits a
   * `console.warn` so an operator skimming devtools can't miss it.
   */
  private isMockConnection = false;

  constructor(opts: KawiriClientOptions) {
    this.options = {
      url: opts.url,
      validator: opts.validator ?? new StubValidator(),
      enablePQ: opts.enablePQ ?? true,
      connectTimeout: opts.connectTimeout ?? 10000,
      debug: opts.debug ?? false,
      onDisconnect: opts.onDisconnect ?? (() => {}),
    };
  }

  get connected(): boolean {
    return this._connected;
  }

  /** Timing breakdown of the last connect() call. Available after connect resolves. */
  get timing(): ConnectTiming | null {
    return this._timing;
  }

  async connect(): Promise<void> {
    const staticKeypair = X25519.generateKeypair();
    const hs = new HandshakeState(true, staticKeypair);
    await hs.initialize();

    const t0 = performance.now();
    const timing: ConnectTiming = { wsOpen: 0, noiseMsg1: 0, validation: 0, noiseMsg2: 0, xwingUpgrade: 0, total: 0 };
    const dbg = this.options.debug ? console.debug.bind(console) : () => {};

    return new Promise<void>((resolveConnect, rejectConnect) => {
      let settled = false;
      const doSettle = (ok: boolean, err?: Error) => {
        if (settled) return;
        settled = true;
        timing.total = performance.now() - t0;
        this._timing = timing;
        if (this.options.debug) {
          dbg(
            `[kawiri] connect timing: ws=${timing.wsOpen.toFixed(0)}ms msg1=${timing.noiseMsg1.toFixed(0)}ms validate=${timing.validation.toFixed(0)}ms msg2=${timing.noiseMsg2.toFixed(0)}ms xwing=${timing.xwingUpgrade.toFixed(0)}ms total=${timing.total.toFixed(0)}ms`,
          );
        }
        clearTimeout(timer);
        if (ok) resolveConnect();
        else rejectConnect(err ?? new Error("Unknown connection error"));
      };

      // Connection timeout
      const timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          if (this.ws) {
            this.ws.close();
            this.ws = null;
          }
          rejectConnect(new Error("Connection timeout"));
        }
      }, this.options.connectTimeout);

      const ws = new WebSocket(this.options.url);
      ws.binaryType = "arraybuffer";
      this.ws = ws;

      let step = 0;
      // For XWing upgrade message passing
      let upgradeResolve: ((data: Uint8Array) => void) | null = null;

      // Message queue — prevents re-entrant onmessage when async
      // handlers yield (e.g. server sends XWing key before split() completes)
      const msgQueue: Uint8Array[] = [];
      let processing = false;

      ws.onopen = async () => {
        try {
          timing.wsOpen = performance.now() - t0;
          dbg(`[kawiri] ws open: ${timing.wsOpen.toFixed(0)}ms`);
          // msg 0: send ephemeral
          const msg0 = await hs.writeMessage();
          ws.send(msg0 as Uint8Array<ArrayBuffer>);
          step = 1;
        } catch (err) {
          doSettle(false, err as Error);
        }
      };

      ws.onmessage = async (event: MessageEvent) => {
        msgQueue.push(new Uint8Array(event.data as ArrayBuffer));
        if (processing) return;
        processing = true;
        try {
          while (msgQueue.length > 0) {
            const data = msgQueue.shift();
            if (!data) break;
            await processMessage(data);
          }
        } finally {
          processing = false;
        }
      };

      const processMessage = async (data: Uint8Array) => {
        try {
          if (step === 1) {
            // msg 1: read responder's ephemeral + static + attestation
            const tMsg1 = performance.now();
            const payloadBytes = await hs.readMessage(data);
            const attestation: AttestationPayload = JSON.parse(new TextDecoder().decode(payloadBytes));
            const remoteStatic = hs.getRemoteStatic();
            if (!remoteStatic) throw new Error("Remote static key not available after handshake read");
            timing.noiseMsg1 = performance.now() - tMsg1;
            dbg(`[kawiri] msg1 (noise read + server attestation): ${timing.noiseMsg1.toFixed(0)}ms`);

            // Validate attestation
            const tValidate = performance.now();
            const result = await this.options.validator.validate(attestation, remoteStatic);
            timing.validation = performance.now() - tValidate;
            dbg(`[kawiri] attestation validation: ${timing.validation.toFixed(0)}ms`);
            if (!result.valid) {
              ws.close(4008, "Attestation validation failed");
              doSettle(false, new Error("Attestation validation failed"));
              return;
            }
            this.isMockConnection = result.mode === "mock";
            if (this.isMockConnection) {
              console.warn(
                "[kawiri] ⚠ Connection established to MOCK kawa — no TEE attestation. " +
                  "Every message on this connection will emit a warning. Production validators reject this.",
              );
            }

            // msg 2: send our static + split
            const tMsg2 = performance.now();
            const msg2 = await hs.writeMessage();
            ws.send(msg2 as Uint8Array<ArrayBuffer>);
            this.transport = await hs.split();
            timing.noiseMsg2 = performance.now() - tMsg2;
            dbg(`[kawiri] msg2 (noise write + split): ${timing.noiseMsg2.toFixed(0)}ms`);
            step = 2;

            if (this.options.enablePQ) {
              // XWing upgrade
              const tXwing = performance.now();
              const send = async (d: Uint8Array) => {
                const ct = await this.transport?.encrypt(d);
                ws.send(ct as Uint8Array<ArrayBuffer>);
              };
              const _receive = () =>
                new Promise<Uint8Array>((resolve) => {
                  upgradeResolve = resolve;
                });

              // Pre-set upgradeResolve before launching clientUpgrade so the
              // message loop can route the server's XWing msg1 even if it
              // arrives before the clientUpgrade microtask runs.
              const upgradePromise = new Promise<Uint8Array>((resolve) => {
                upgradeResolve = resolve;
              });
              const wrappedReceive = () => upgradePromise;

              // Start client upgrade (will wait for server's public key)
              XWingUpgrade.clientUpgrade(this.transport, send, wrappedReceive).then(
                () => {
                  timing.xwingUpgrade = performance.now() - tXwing;
                  dbg(`[kawiri] xwing upgrade: ${timing.xwingUpgrade.toFixed(0)}ms`);
                  upgradeResolve = null;
                  step = 3;
                  this._connected = true;
                  doSettle(true);
                },
                (err) => doSettle(false, err),
              );
            } else {
              step = 3;
              this._connected = true;
              doSettle(true);
            }
          } else if (step === 2 && upgradeResolve) {
            // During XWing upgrade: decrypt and pass to upgrade handler
            if (!this.transport) throw new Error("transport not established");
            const pt = await this.transport.decrypt(data);
            upgradeResolve(pt);
          } else if (step >= 3 && this.transport) {
            // Transport mode: decrypt, deframe, route
            await this.handleTransportMessage(data);
          }
        } catch (err) {
          if (step < 3) {
            doSettle(false, err as Error);
          } else {
            console.error("[klient] Error:", err);
          }
        }
      };

      ws.onerror = (event) => {
        const msg = event instanceof ErrorEvent ? event.message : "WebSocket error";
        doSettle(false, new Error(msg));
      };

      ws.onclose = (event) => {
        this._connected = false;
        this.transport = null;
        // Reject all pending requests
        for (const [, p] of this.pending) {
          p.reject(new Error("Connection closed"));
        }
        this.pending.clear();

        if (settled) {
          // Post-connect disconnect
          this.options.onDisconnect(event.reason || "Connection closed");
        } else {
          doSettle(false, new Error("Connection closed before handshake completed"));
        }
      };
    });
  }

  private async handleTransportMessage(data: Uint8Array): Promise<void> {
    if (!this.transport) throw new Error("transport not established");
    if (this.isMockConnection) {
      console.warn("[kawiri] ⚠ recv on MOCK connection (no TEE backing this transport)");
    }
    const plainFrame = await this.transport.decrypt(data);
    const decoded = Framer.decode(plainFrame);

    let payload: Uint8Array | null;
    if (decoded.flag === 0) {
      payload = decoded.payload;
    } else {
      payload = this.assembler.processFrame(decoded);
    }

    if (!payload) return;

    let json: Record<string, unknown>;
    try {
      json = JSON.parse(new TextDecoder().decode(payload));
    } catch {
      console.error("[kawiri] malformed transport frame (invalid JSON)");
      return;
    }

    // Check if it's a stream chunk or a response
    if ("event" in json) {
      const chunk = json as unknown as KawiriStreamChunk;
      const p = this.pending.get(chunk.id);
      if (!p) return;

      // Handle errors for both streaming and non-streaming requests
      if (chunk.event === "error") {
        if (p.stream) {
          p.stream.error(new Error(String(chunk.data)));
        } else {
          p.reject(new Error(String(chunk.data)));
        }
        this.pending.delete(chunk.id);
        return;
      }

      if (!p.stream) return;

      if (chunk.event === "data" && chunk.data) {
        // Parse SSE data if it's a string
        try {
          const parsed = typeof chunk.data === "string" ? JSON.parse(chunk.data) : chunk.data;
          const content = parsed?.choices?.[0]?.delta?.content ?? parsed?.choices?.[0]?.message?.content ?? "";
          if (content) {
            p.stream.enqueue(content);
          }
        } catch {
          // Not JSON, enqueue raw
          p.stream.enqueue(String(chunk.data));
        }
      } else if (chunk.event === "done") {
        p.stream.close();
        this.pending.delete(chunk.id);
      }
    } else {
      const resp = json as unknown as KawiriResponse;
      const p = this.pending.get(resp.id);
      if (!p) return;
      this.pending.delete(resp.id);

      // Extract structured result — OpenAI-compatible or plain
      const body = resp.body;
      if (body && typeof body === "object" && "choices" in body) {
        const obj = body as Record<string, unknown>;
        const choices = obj.choices as { message?: { content?: string }; finish_reason?: string }[] | undefined;
        const choice = choices?.[0];
        p.resolve({
          content: choice?.message?.content ?? "",
          usage: obj.usage as ChatResult["usage"],
          model: obj.model as string | undefined,
          finish_reason: choice?.finish_reason,
        } satisfies ChatResult);
      } else {
        // Non-chat endpoints (e.g. /ping) — use raw body as content
        p.resolve({
          content: typeof body === "string" ? body : JSON.stringify(body ?? ""),
        } satisfies ChatResult);
      }
    }
  }

  private async sendRequest(req: KawiriRequest): Promise<void> {
    if (!this._connected || !this.transport || !this.ws) {
      throw new Error("Not connected");
    }
    if (this.isMockConnection) {
      console.warn("[kawiri] ⚠ send on MOCK connection (no TEE backing this transport)");
    }
    const json = JSON.stringify(req);
    const data = new TextEncoder().encode(json);
    const frames = Framer.encode(data);
    for (const frame of frames) {
      const encrypted = await this.transport.encrypt(frame);
      this.ws.send(encrypted as Uint8Array<ArrayBuffer>);
    }
  }

  /** Send an arbitrary request and get the response. */
  async request(method: "GET" | "POST", path: string, body?: unknown): Promise<ChatResult> {
    const id = this.nextId++;
    return new Promise<ChatResult>((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.sendRequest({ id, method, path, body }).catch(reject);
    });
  }

  /** Non-streaming chat */
  async chat(messages: ChatMessage[], model = "default", options?: ChatOptions): Promise<ChatResult> {
    const id = this.nextId++;
    return new Promise<ChatResult>((resolve, reject) => {
      this.pending.set(id, {
        resolve: resolve as (v: unknown) => void,
        reject,
      });
      this.sendRequest({
        id,
        method: "POST",
        path: "/v1/chat/completions",
        body: { ...options, messages, model, stream: false },
      }).catch(reject);
    });
  }

  /** Streaming chat — returns a ReadableStream of content tokens */
  chatStream(messages: ChatMessage[], model = "default", options?: ChatOptions): ReadableStream<string> {
    const id = this.nextId++;

    const stream = new ReadableStream<string>({
      start: (c) => {
        this.pending.set(id, {
          resolve: () => {},
          reject: (err) => c.error(err),
          stream: c,
        });
        this.sendRequest({
          id,
          method: "POST",
          path: "/v1/chat/completions",
          body: { ...options, messages, model, stream: true },
        }).catch((err) => c.error(err));
      },
    });

    return stream;
  }

  close(): void {
    if (this.ws) {
      this.ws.close(1000, "Client closed");
      this.ws = null;
    }
    this._connected = false;
  }
}
