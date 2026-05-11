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
  /**
   * Called once per request when the server reports usage. Only fires
   * when kawa speaks the `kawiri.v2` subprotocol — older kawa never
   * emits a metering frame. The event shape mirrors OpenAI's `usage`
   * block plus our routing identifiers (req_id, model, duration).
   */
  onUsage?: (event: UsageEvent) => void;
  /**
   * Offer the `kawiri.v2` WebSocket subprotocol on upgrade. When the
   * server accepts it (`ws.protocol === "kawiri.v2"`), every binary
   * WS frame carries a one-byte type tag (0x01 encrypted / 0x02
   * cleartext metering). Default false — explicit opt-in keeps the
   * legacy path the source of truth for clients that talk directly
   * to kawa, and only the api.kawiri.ai router insists on v2.
   */
  enableV2?: boolean;
}

export interface UsageEvent {
  object: "kawiri.usage";
  req_id?: number;
  model?: string;
  usage?: {
    prompt_tokens?: number;
    completion_tokens?: number;
    total_tokens?: number;
  };
  duration_ms?: number;
  finish_reason?: string;
}

// Wire-protocol tags used when the WebSocket subprotocol negotiates
// `kawiri.v2`. When v1 is in effect (no subprotocol), every frame's
// payload is the Noise ciphertext directly and these tags don't apply.
const FRAME_ENCRYPTED = 0x01;
const FRAME_METERING = 0x02;
const KAWIRI_V2 = "kawiri.v2";

interface PendingRequest {
  resolve: (value: ChatResult) => void;
  reject: (err: Error) => void;
  stream?: ReadableStreamDefaultController<string>;
  /**
   * True between the first `delta.reasoning_content` token and the
   * first `delta.content` token (or stream end). Lets us emit
   * synthetic `<think>` / `</think>` markers around the reasoning
   * stream so downstream consumers (chat's Transcript) can render
   * the reasoning as a separate panel without speaking llama.cpp's
   * extended OpenAI schema. Reset between requests.
   */
  reasoningOpen?: boolean;
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
   * Emits a single warn at handshake completion (see connect()); per-frame
   * warns were dropped because they flooded devtools without adding signal.
   */
  private isMockConnection = false;
  /**
   * True when the server accepted the `kawiri.v2` subprotocol on
   * upgrade. While true, every binary WS frame carries a leading
   * byte tag: 0x01 = encrypted Noise payload (existing behavior
   * shifted by 1 byte), 0x02 = cleartext metering JSON. While false
   * (old kawa), frames are untagged and metering doesn't exist.
   */
  private v2 = false;

  constructor(opts: KawiriClientOptions) {
    this.options = {
      url: opts.url,
      validator: opts.validator ?? new StubValidator(),
      enablePQ: opts.enablePQ ?? true,
      connectTimeout: opts.connectTimeout ?? 10000,
      debug: opts.debug ?? false,
      onDisconnect: opts.onDisconnect ?? (() => {}),
      onUsage: opts.onUsage ?? (() => {}),
      enableV2: opts.enableV2 ?? false,
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

      // Offer the v2 subprotocol only when the caller opts in. The
      // router (api.kawiri.ai) enables this; legacy direct-to-kawa
      // clients stay on the untagged path so their existing servers
      // — which know nothing about subprotocols — continue working.
      const ws = this.options.enableV2 ? new WebSocket(this.options.url, [KAWIRI_V2]) : new WebSocket(this.options.url);
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
          // Only treat the connection as v2 if we BOTH asked for v2 AND
          // the server echoed `kawiri.v2`. Belt-and-braces: some
          // WebSocket runtimes report a non-empty `ws.protocol` even
          // when the server didn't explicitly negotiate one, which
          // would otherwise misframe every frame as tagged.
          this.v2 = (this.options.enableV2 ?? false) && ws.protocol === KAWIRI_V2;
          dbg(`[kawiri] subprotocol: ${ws.protocol || "(none, v1)"} · v2=${this.v2}`);
          // msg 0: send ephemeral
          const msg0 = await hs.writeMessage();
          ws.send(wrapOutbound(msg0, this.v2) as Uint8Array<ArrayBuffer>);
          step = 1;
        } catch (err) {
          doSettle(false, err as Error);
        }
      };

      ws.onmessage = async (event: MessageEvent) => {
        const raw = new Uint8Array(event.data as ArrayBuffer);
        // Demux the v2 frame-type tag here so the rest of the receive
        // pipeline is untouched. Metering frames (0x02) skip the queue
        // entirely; they're plaintext and have nothing to do with the
        // Noise transport. Encrypted frames (0x01) get the tag stripped
        // and flow on as if v1.
        const payload = this.v2 ? this.handleTaggedFrame(raw) : raw;
        if (!payload) return; // was metering; consumed by handler
        msgQueue.push(payload);
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
                  "Production validators reject this.",
              );
            }

            // msg 2: send our static + split
            const tMsg2 = performance.now();
            const msg2 = await hs.writeMessage();
            ws.send(wrapOutbound(msg2, this.v2) as Uint8Array<ArrayBuffer>);
            this.transport = await hs.split();
            timing.noiseMsg2 = performance.now() - tMsg2;
            dbg(`[kawiri] msg2 (noise write + split): ${timing.noiseMsg2.toFixed(0)}ms`);
            step = 2;

            if (this.options.enablePQ) {
              // XWing upgrade
              const tXwing = performance.now();
              const send = async (d: Uint8Array) => {
                const ct = await this.transport?.encrypt(d);
                if (!ct) return;
                ws.send(wrapOutbound(ct, this.v2) as Uint8Array<ArrayBuffer>);
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

  /**
   * Demux a v2-tagged inbound WS frame.
   * Returns the encrypted Noise payload (tag stripped) for the caller
   * to feed into the existing handshake/transport pipeline, or null
   * when the frame was a metering envelope and has been consumed here.
   */
  private handleTaggedFrame(raw: Uint8Array): Uint8Array | null {
    if (raw.length === 0) return raw;
    const tag = raw[0];
    if (tag === FRAME_METERING) {
      // Cleartext JSON usage envelope from kawa. Hand it to the caller
      // via the onUsage hook; never decrypt, never queue.
      try {
        const body = new TextDecoder().decode(raw.subarray(1));
        const event = JSON.parse(body) as UsageEvent;
        this.options.onUsage(event);
      } catch (e) {
        console.warn("[kawiri] dropped malformed metering frame", e);
      }
      return null;
    }
    if (tag !== FRAME_ENCRYPTED) {
      // Unknown tag — neither a Noise frame nor a metering one. Old
      // servers shouldn't emit anything tagged at all; new ones only
      // emit 0x01 or 0x02. Drop with a warning to surface protocol
      // drift if it ever happens.
      console.warn(`[kawiri] dropped frame with unknown tag 0x${tag.toString(16)}`);
      return null;
    }
    return raw.subarray(1);
  }

  private async handleTransportMessage(data: Uint8Array): Promise<void> {
    if (!this.transport) throw new Error("transport not established");
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
          const delta = parsed?.choices?.[0]?.delta;
          const reasoning: string = delta?.reasoning_content ?? parsed?.choices?.[0]?.message?.reasoning_content ?? "";
          const content: string = delta?.content ?? parsed?.choices?.[0]?.message?.content ?? "";

          // Reasoning tokens are wrapped in synthetic <think>...</think>
          // markers so chat's Transcript renders them as a Reasoning
          // panel without needing per-token type info. Open the wrapper
          // on the first reasoning token, close it the moment the
          // first non-empty content token arrives.
          if (reasoning) {
            if (!p.reasoningOpen) {
              p.stream.enqueue("<think>");
              p.reasoningOpen = true;
            }
            p.stream.enqueue(reasoning);
          }
          if (content) {
            if (p.reasoningOpen) {
              p.stream.enqueue("</think>");
              p.reasoningOpen = false;
            }
            p.stream.enqueue(content);
          }
        } catch {
          // Not JSON, enqueue raw
          p.stream.enqueue(String(chunk.data));
        }
      } else if (chunk.event === "done") {
        // Edge case: stream ended mid-reasoning (max_tokens cut in before
        // the answer started). Close the synthetic <think> so the UI
        // doesn't render an open-ended reasoning block.
        if (p.reasoningOpen) {
          p.stream.enqueue("</think>");
          p.reasoningOpen = false;
        }
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
        const choices = obj.choices as
          | {
              message?: { content?: string; reasoning_content?: string };
              finish_reason?: string;
            }[]
          | undefined;
        const choice = choices?.[0];
        const reasoning = choice?.message?.reasoning_content ?? "";
        const answer = choice?.message?.content ?? "";
        // Mirror the streaming path: wrap reasoning_content in
        // <think>...</think> so callers parsing combined content see
        // the same shape as a streamed response.
        const content = reasoning ? `<think>${reasoning}</think>${answer}` : answer;
        p.resolve({
          content,
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
    const json = JSON.stringify(req);
    const data = new TextEncoder().encode(json);
    const frames = Framer.encode(data);
    for (const frame of frames) {
      const encrypted = await this.transport.encrypt(frame);
      this.ws.send(wrapOutbound(encrypted, this.v2) as Uint8Array<ArrayBuffer>);
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

/**
 * Tag an outbound frame with the v2 encrypted-tag byte (0x01).
 * When v2 isn't in effect, the frame goes out as-is (legacy untagged).
 * Lives outside the class so it's trivial to test in isolation.
 */
function wrapOutbound(payload: Uint8Array, v2: boolean): Uint8Array {
  if (!v2) return payload;
  const out = new Uint8Array(payload.length + 1);
  out[0] = FRAME_ENCRYPTED;
  out.set(payload, 1);
  return out;
}
