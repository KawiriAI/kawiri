/**
 * `konnect serve` — OpenAI-compatible local proxy in front of the
 * Kawiri encrypted+attested tunnel.
 *
 *   localhost:<port>  ←  plain OpenAI HTTP/SSE  ←  user's tool
 *         │
 *         ▼
 *   one long-lived KawiriClient over wss://api.kawiri.ai/v1/chat
 *         │
 *         ▼  (Noise XX + attestation + X-Wing PQ)
 *   kawa inside the CVM, reverse-proxies to local llama.cpp/vllm
 *
 * One model per process: the WS upgrade carries `?model=<image>` and
 * every request on the same WS routes to that image. Aliases let
 * multiple OpenAI-shaped model names resolve to the same image
 * (handy for tools that hardcode "gpt-4o-mini").
 *
 * Why a local proxy at all: kawa's tunnel is a custom Noise/X-Wing
 * over WebSocket protocol. No OpenAI client speaks that. The proxy
 * runs on the user's machine — inside the trust boundary the tunnel
 * already terminates at — so it can decrypt and translate without
 * weakening the E2E guarantee.
 */
import { type ChatMessage, type ChatOptions, KawiriClient, KattValidator, StubValidator } from "../core/mod.ts";
import { parseArgs, resolveConfig, type ServeConfig } from "./config.ts";

export async function serveCmd(argv: readonly string[]): Promise<number> {
	let cfg: ServeConfig;
	try {
		const rawArgs = parseArgs(argv);
		cfg = await resolveConfig(rawArgs, process.env);
	} catch (e) {
		const msg = e instanceof Error ? e.message : String(e);
		process.stderr.write(`konnect serve: ${msg}\n`);
		return 2;
	}

	logEffectiveConfig(cfg);

	const validator = cfg.allow_mock_attestation
		? new KattValidator({ allowMock: true, liveCollateral: true })
		: new KattValidator({ allowMock: false, liveCollateral: true });

	const upstreamUrl = appendModelToUrl(cfg.target, cfg.model);
	const client = new KawiriClient({
		url: upstreamUrl,
		validator,
		enablePQ: cfg.enable_pq,
		debug: false,
		webSocketFactory: (url) => bunWebSocketWithAuth(url, cfg.api_key),
		onDisconnect: (reason) => {
			console.warn(`[konnect serve] tunnel disconnected: ${reason}`);
			// We'll lazily reconnect on next request.
			state.connected = false;
		},
	});

	const state = {
		connected: false,
		connecting: false as Promise<void> | false,
		client,
	};

	const ensureConnected = async (): Promise<void> => {
		if (state.connected) return;
		if (state.connecting) return state.connecting;
		state.connecting = (async () => {
			try {
				await client.connect();
				state.connected = true;
			} finally {
				state.connecting = false;
			}
		})();
		return state.connecting;
	};

	// Eager connect: fail fast if the api_key is bad or attestation
	// fails. Operator sees the error immediately instead of on first
	// request.
	try {
		await ensureConnected();
		console.log("[konnect serve] tunnel ready (attestation verified)");
	} catch (e) {
		const msg = e instanceof Error ? e.message : String(e);
		process.stderr.write(`konnect serve: failed to establish tunnel: ${msg}\n`);
		return 1;
	}

	// HTTP listener. Bun.serve is the simplest option that supports
	// streaming responses cleanly via ReadableStream.
	const server = Bun.serve({
		hostname: cfg.bind,
		port: cfg.port,
		fetch: async (req) => handleRequest(req, cfg, state, ensureConnected),
	});

	console.log(`[konnect serve] listening on http://${server.hostname}:${server.port}`);
	console.log(`[konnect serve] model: ${cfg.model}`);
	if (Object.keys(cfg.aliases).length > 0) {
		console.log(`[konnect serve] aliases: ${Object.keys(cfg.aliases).join(", ")}`);
	}

	// Block forever — Bun.serve doesn't keep the event loop alive on
	// its own when called from a top-level await.
	return await new Promise<number>(() => {
		// Never resolves; rely on Ctrl-C to terminate.
	});
}

interface ProxyState {
	connected: boolean;
	connecting: Promise<void> | false;
	client: KawiriClient;
}

async function handleRequest(
	req: Request,
	cfg: ServeConfig,
	state: ProxyState,
	ensureConnected: () => Promise<void>,
): Promise<Response> {
	const url = new URL(req.url);
	const path = url.pathname;

	// Inbound bearer enforcement, if configured. Default policy: any
	// bearer (or none) is fine on loopback. Operator opts into a strict
	// check by setting [security].local_token.
	if (cfg.local_token) {
		const provided = (req.headers.get("Authorization") ?? "").replace(/^Bearer\s+/i, "");
		if (provided !== cfg.local_token) {
			return jsonError(401, "unauthorized", "inbound bearer does not match KONNECT_LOCAL_TOKEN");
		}
	}

	// Liveness probe — pure local, doesn't require the tunnel.
	if (path === "/healthz") {
		return new Response("ok\n", { status: 200, headers: { "content-type": "text/plain" } });
	}

	// Readiness — only ok if the tunnel is attested + connected.
	if (path === "/readyz") {
		return state.connected
			? new Response("ok\n", { status: 200, headers: { "content-type": "text/plain" } })
			: new Response("tunnel not ready\n", { status: 503, headers: { "content-type": "text/plain" } });
	}

	// Synthesized model list — the engine inside the CVM serves one
	// model per process, so we tell tools about it plus every alias.
	if (req.method === "GET" && (path === "/v1/models" || path === "/v1/models/")) {
		return Response.json(modelsResponse(cfg));
	}

	// Anything else must hit the tunnel. Reconnect lazily if needed.
	try {
		await ensureConnected();
	} catch (e) {
		const msg = e instanceof Error ? e.message : String(e);
		return jsonError(502, "tunnel_unavailable", msg);
	}

	// Streaming chat — special-case because we re-encode konnect's
	// plain token stream as OpenAI SSE chunks.
	if (req.method === "POST" && path === "/v1/chat/completions") {
		return handleChatCompletions(req, cfg, state.client);
	}

	// Generic passthrough for any other /v1/* the engine supports
	// (embeddings, completions, audio/*, images/*, …). konnect's
	// `request()` already speaks the framed JSON shape; the upstream
	// engine returns OpenAI-shaped JSON which we relay verbatim.
	if (path.startsWith("/v1/")) {
		const method = req.method as "GET" | "POST";
		if (method !== "GET" && method !== "POST") {
			return jsonError(405, "method_not_allowed", `unsupported method: ${req.method}`);
		}
		let body: unknown;
		if (method === "POST") {
			try {
				body = await req.json();
			} catch {
				return jsonError(400, "bad_request", "POST body must be valid JSON");
			}
		}
		try {
			const upstream = await state.client.request(method, path, body);
			// konnect's `request()` returns ChatResult-shaped, but for
			// non-chat endpoints the engine returns its native JSON.
			// kawa packs that into ChatResult.content as a JSON-stringified
			// blob (or returns the body verbatim — depends on the kawa
			// proxy shape). We return whatever shape we got.
			return Response.json(upstream);
		} catch (e) {
			const msg = e instanceof Error ? e.message : String(e);
			return jsonError(502, "tunnel_error", msg);
		}
	}

	return jsonError(404, "not_found", `${req.method} ${path}`);
}

/** OpenAI `/v1/models` response shape. Synthesized — the upstream
 *  engine inside the CVM is single-image; we report the configured
 *  image plus any aliases as separate model rows so tools see what
 *  they expect. */
function modelsResponse(cfg: ServeConfig): unknown {
	const created = Math.floor(Date.now() / 1000);
	const rows = [
		{ id: cfg.model, object: "model", created, owned_by: "kawiri" },
		...Object.keys(cfg.aliases).map((alias) => ({
			id: alias,
			object: "model",
			created,
			owned_by: "kawiri",
		})),
	];
	return { object: "list", data: rows };
}

interface ChatCompletionRequest {
	model?: string;
	messages?: ChatMessage[];
	stream?: boolean;
	temperature?: number;
	max_tokens?: number;
	top_p?: number;
	frequency_penalty?: number;
	presence_penalty?: number;
	stop?: string | string[];
}

async function handleChatCompletions(req: Request, cfg: ServeConfig, client: KawiriClient): Promise<Response> {
	let body: ChatCompletionRequest;
	try {
		body = (await req.json()) as ChatCompletionRequest;
	} catch {
		return jsonError(400, "bad_request", "POST body must be valid JSON");
	}
	if (!Array.isArray(body.messages) || body.messages.length === 0) {
		return jsonError(400, "bad_request", "messages array required");
	}

	// Model resolution: incoming alias → configured kcvm image. The
	// upstream WS is already pinned to the configured image, so the
	// `model` we ship in the body is purely advisory for the engine.
	const requestedModel = body.model ?? cfg.model;
	const resolvedModel = cfg.aliases[requestedModel] ?? requestedModel;
	if (resolvedModel !== cfg.model && !Object.values(cfg.aliases).includes(resolvedModel)) {
		// Unknown model — the WS is pinned elsewhere. Tools that ask
		// for a model we can't serve should get a clear refusal, not
		// silent rerouting. (We don't bother spinning up a second
		// tunnel in v0.)
		return jsonError(404, "model_not_found", `model '${requestedModel}' not configured on this proxy`);
	}

	const options: ChatOptions = {};
	if (typeof body.temperature === "number") options.temperature = body.temperature;
	if (typeof body.max_tokens === "number") options.max_tokens = body.max_tokens;
	if (typeof body.top_p === "number") options.top_p = body.top_p;
	if (typeof body.frequency_penalty === "number") options.frequency_penalty = body.frequency_penalty;
	if (typeof body.presence_penalty === "number") options.presence_penalty = body.presence_penalty;
	if (body.stop !== undefined) options.stop = body.stop;

	const chatId = `chatcmpl-${randomHex(16)}`;
	const created = Math.floor(Date.now() / 1000);
	const advertisedModel = requestedModel;

	if (body.stream === true) {
		// Streaming SSE.
		const tokenStream = client.chatStream(body.messages, resolvedModel, options);
		const sse = renderSse(tokenStream, chatId, created, advertisedModel);
		return new Response(sse, {
			status: 200,
			headers: {
				"content-type": "text/event-stream",
				"cache-control": "no-cache, no-transform",
				connection: "keep-alive",
				"x-accel-buffering": "no", // hint to any intermediaries
			},
		});
	}

	// Non-streaming: aggregate the stream into a single response.
	// We use chat() rather than chatStream() so the upstream can
	// optimize (some engines have a faster path for non-streaming).
	try {
		const result = await client.chat(body.messages, resolvedModel, options);
		return Response.json({
			id: chatId,
			object: "chat.completion",
			created,
			model: advertisedModel,
			choices: [
				{
					index: 0,
					message: { role: "assistant", content: result.content },
					finish_reason: result.finish_reason ?? "stop",
				},
			],
			usage: result.usage ?? {
				prompt_tokens: 0,
				completion_tokens: 0,
				total_tokens: 0,
			},
		});
	} catch (e) {
		const msg = e instanceof Error ? e.message : String(e);
		return jsonError(502, "upstream_error", msg);
	}
}

/**
 * Wrap konnect's plain-token ReadableStream into the OpenAI SSE
 * chunk format. Emits:
 *
 *   1. A `role: "assistant"` chunk first (no content).
 *   2. One chunk per token, `delta.content = "<token>"`.
 *   3. A final chunk with `finish_reason = "stop"` and empty delta.
 *   4. The `data: [DONE]\n\n` sentinel.
 *
 * Errors mid-stream are surfaced as a chunk with `finish_reason =
 * "error"` plus a final [DONE] so the client closes cleanly rather
 * than hanging on a dropped connection.
 */
export function renderSse(
	tokens: ReadableStream<string>,
	chatId: string,
	created: number,
	model: string,
): ReadableStream<Uint8Array> {
	const enc = new TextEncoder();
	const reader = tokens.getReader();

	return new ReadableStream<Uint8Array>({
		async start(c) {
			c.enqueue(enc.encode(sseChunk(chatId, created, model, { role: "assistant" }, null)));
			try {
				while (true) {
					const { value, done } = await reader.read();
					if (done) break;
					c.enqueue(enc.encode(sseChunk(chatId, created, model, { content: value }, null)));
				}
				c.enqueue(enc.encode(sseChunk(chatId, created, model, {}, "stop")));
				c.enqueue(enc.encode("data: [DONE]\n\n"));
			} catch (e) {
				const msg = e instanceof Error ? e.message : String(e);
				// Surface the error in-band so the client sees something
				// before the stream closes. Non-standard `error` finish
				// reason matches what OpenAI does in some failure modes.
				c.enqueue(
					enc.encode(
						sseChunk(chatId, created, model, { content: `\n\n[stream error: ${msg}]` }, "error"),
					),
				);
				c.enqueue(enc.encode("data: [DONE]\n\n"));
			} finally {
				c.close();
				reader.releaseLock();
			}
		},
		cancel() {
			// Client aborted (closed their connection mid-stream). Stop
			// pulling tokens from the upstream so we don't keep the
			// inference engine producing for a dead consumer.
			reader.cancel().catch(() => {});
		},
	});
}

function sseChunk(
	id: string,
	created: number,
	model: string,
	delta: { role?: string; content?: string },
	finish: string | null,
): string {
	const payload = {
		id,
		object: "chat.completion.chunk",
		created,
		model,
		choices: [{ index: 0, delta, finish_reason: finish }],
	};
	return `data: ${JSON.stringify(payload)}\n\n`;
}

/**
 * Bun-only WebSocket constructor that injects an Authorization header.
 * Browsers can't set custom WS headers, but Bun (and Node's `ws` and
 * Deno's WebSocketStream) support an options-bag second argument with
 * a `headers` field. The cast to `string[]` is a lie to TypeScript's
 * browser-flavored DOM types so the same library compiles for both.
 */
function bunWebSocketWithAuth(url: string, bearer: string): WebSocket {
	const opts = { headers: { Authorization: `Bearer ${bearer}` } } as unknown as string[];
	return new WebSocket(url, opts);
}

/** Append `?model=<image>` to the WS URL, preserving any existing query. */
function appendModelToUrl(url: string, model: string): string {
	// We can't use the URL class with `wss:` directly in all runtimes,
	// but it works in Bun. Fall back to a string-append on parse error.
	try {
		const u = new URL(url);
		u.searchParams.set("model", model);
		return u.toString();
	} catch {
		const sep = url.includes("?") ? "&" : "?";
		return `${url}${sep}model=${encodeURIComponent(model)}`;
	}
}

function jsonError(status: number, code: string, message: string): Response {
	return Response.json({ error: { code, message } }, { status });
}

function randomHex(bytes: number): string {
	const buf = new Uint8Array(bytes);
	crypto.getRandomValues(buf);
	return Array.from(buf, (b) => b.toString(16).padStart(2, "0")).join("");
}

function logEffectiveConfig(cfg: ServeConfig): void {
	console.log("[konnect serve] effective config:");
	console.log(`  target:    ${cfg.target}`);
	console.log(`  model:     ${cfg.model}`);
	console.log(`  bind:      ${cfg.bind}:${cfg.port}`);
	console.log(`  api_key:   ${cfg.api_key.slice(0, 6)}…${cfg.api_key.slice(-4)} (${cfg.api_key.length} chars)`);
	console.log(`  pq:        ${cfg.enable_pq ? "on" : "off"}`);
	console.log(`  mock_att:  ${cfg.allow_mock_attestation ? "ALLOWED (INSECURE)" : "off"}`);
	console.log(`  local_tok: ${cfg.local_token ? "set" : "not set"}`);
	if (Object.keys(cfg.aliases).length > 0) {
		console.log("  aliases:");
		for (const [from, to] of Object.entries(cfg.aliases)) {
			console.log(`    ${from} → ${to}`);
		}
	}
}

// Silence unused import warnings — StubValidator is referenced indirectly
// via the KattValidator fallback comment above.
void StubValidator;
