/**
 * `konnect serve` — OpenAI-compatible local proxy in front of the
 * Kawiri encrypted+attested tunnel.
 *
 *   localhost:<port>  ←  plain OpenAI HTTP/SSE  ←  user's tool
 *         │
 *         ▼
 *   ClientPool — one KawiriClient per configured kcvm image, sharing
 *   one bearer. Each image's WS does its own Noise + attestation +
 *   X-Wing PQ on first use; idle clients evict on a timer.
 *         │
 *         ▼
 *   wss://api.kawiri.ai/v1/chat?model=<image>
 *         │
 *         ▼
 *   teehost mTLS → kawa inside the CVM → llama.cpp / vllm / sglang
 *
 * Two HTTP surfaces:
 *
 *   1. Chat completions are re-encoded — streaming chunks become
 *      OpenAI SSE, non-streaming becomes a single chat.completion
 *      JSON. Necessary because konnect's protocol carries plain
 *      content tokens, not OpenAI's chunk envelope.
 *
 *   2. Everything else under /v1/* is forwarded raw via
 *      `client.requestRaw()`. Status code + body come back verbatim,
 *      so embeddings, completions, models, audio, images all work
 *      whenever the engine inside the CVM supports them.
 *
 * Why a local proxy at all: the Kawiri tunnel is a custom Noise/X-Wing
 * over WebSocket protocol. No OpenAI client speaks that. The proxy
 * runs on the user's machine — inside the trust boundary the tunnel
 * already terminates at — so it can decrypt and translate without
 * weakening the E2E guarantee.
 */
import { timingSafeEqual } from "node:crypto";
import { type ChatMessage, type ChatOptions, type KawiriClient } from "../core/mod.ts";
import { parseArgs, resolveConfig, type ServeConfig } from "./config.ts";
import { ClientPool } from "./pool.ts";

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

	const pool = new ClientPool({
		target: cfg.target,
		bearer: cfg.api_key,
		allowedImages: new Set(cfg.models),
		enablePQ: cfg.enable_pq,
		allowMockAttestation: cfg.allow_mock_attestation,
		idleCloseMs: cfg.idle_close_ms,
		livenessProbeAfterMs: cfg.liveness_probe_after_ms,
		livenessProbeTimeoutMs: cfg.liveness_probe_timeout_ms,
		onClientReady: (image) => console.log(`[konnect serve] tunnel ready: ${image}`),
		onClientClosed: (image, reason) => console.warn(`[konnect serve] tunnel closed: ${image} (${reason})`),
	});

	// Eager-connect the default model so attestation failures and bad
	// api_keys surface at startup rather than at the first user request.
	const defaultImage = cfg.models[0]!;
	try {
		await pool.withClient(defaultImage, async () => {});
		console.log(`[konnect serve] tunnel ready (attestation verified, default model: ${defaultImage})`);
	} catch (e) {
		const msg = e instanceof Error ? e.message : String(e);
		process.stderr.write(`konnect serve: failed to establish tunnel: ${msg}\n`);
		await pool.closeAll();
		return 1;
	}

	const server = Bun.serve({
		hostname: cfg.bind,
		port: cfg.port,
		fetch: async (req) => handleRequest(req, cfg, pool),
	});

	console.log(`[konnect serve] listening on http://${server.hostname}:${server.port}`);
	if (cfg.models.length > 1) {
		console.log(`[konnect serve] models: ${cfg.models.join(", ")} (default: ${defaultImage})`);
	}
	if (Object.keys(cfg.aliases).length > 0) {
		console.log(`[konnect serve] aliases: ${Object.keys(cfg.aliases).join(", ")}`);
	}

	// Graceful shutdown: close every pooled WS so kawa sees a proper
	// close frame instead of a TCP RST. SIGINT/SIGTERM both go through
	// the same path; signal arrives mid-request → in-flight stream
	// reads still finish (Bun.serve drains).
	const shutdown = async (signal: string) => {
		console.log(`\n[konnect serve] received ${signal}, draining...`);
		server.stop(true);
		await pool.closeAll();
		process.exit(0);
	};
	process.on("SIGINT", () => void shutdown("SIGINT"));
	process.on("SIGTERM", () => void shutdown("SIGTERM"));

	// Park forever; SIGINT handler exits.
	return await new Promise<number>(() => {});
}

// ── HTTP routing ─────────────────────────────────────────────────

/** Map of path → handler. Order matters: matched top-to-bottom by
 *  exact-path equality (with method check inside the handler). The
 *  one entry that doesn't exact-match (`/v1/*` generic passthrough)
 *  is handled after the table miss. */
type Handler = (req: Request, cfg: ServeConfig, pool: ClientPool) => Promise<Response>;
const ROUTES: Record<string, Handler> = {
	"/healthz": handleHealthz,
	"/readyz": handleReadyz,
	"/v1/models": handleModels,
	"/v1/models/": handleModels,
	"/v1/chat/completions": handleChatCompletions,
};

async function handleRequest(req: Request, cfg: ServeConfig, pool: ClientPool): Promise<Response> {
	const url = new URL(req.url);
	const path = url.pathname;

	const authCheck = enforceLocalToken(cfg, req);
	if (authCheck) return authCheck;

	const route = ROUTES[path];
	if (route) return route(req, cfg, pool);

	// Generic /v1/* passthrough — anything the engine inside the CVM
	// serves works without per-route code.
	if (path.startsWith("/v1/")) return handleGenericV1(req, cfg, pool);

	return jsonError(404, "not_found", `${req.method} ${path}`);
}

// ── handlers ────────────────────────────────────────────────────

async function handleHealthz(): Promise<Response> {
	return new Response("ok\n", { status: 200, headers: { "content-type": "text/plain" } });
}

async function handleReadyz(_req: Request, _cfg: ServeConfig, pool: ClientPool): Promise<Response> {
	// Ready means: pool isn't empty (the eager-opened default model
	// is still alive). Tells consumers (k8s probes, monitoring) when
	// the proxy can actually carry traffic.
	const open = pool.size();
	const status = open > 0 ? 200 : 503;
	return Response.json({ ok: open > 0, clients_open: open, stats: pool.stats() }, { status });
}

async function handleModels(_req: Request, cfg: ServeConfig): Promise<Response> {
	const created = Math.floor(Date.now() / 1000);
	const seen = new Set<string>();
	const rows: { id: string; object: "model"; created: number; owned_by: string }[] = [];
	for (const image of cfg.models) {
		if (seen.has(image)) continue;
		seen.add(image);
		rows.push({ id: image, object: "model", created, owned_by: "kawiri" });
	}
	for (const alias of Object.keys(cfg.aliases)) {
		if (seen.has(alias)) continue;
		seen.add(alias);
		rows.push({ id: alias, object: "model", created, owned_by: "kawiri" });
	}
	return Response.json({ object: "list", data: rows });
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

async function handleChatCompletions(req: Request, cfg: ServeConfig, pool: ClientPool): Promise<Response> {
	if (req.method !== "POST") return jsonError(405, "method_not_allowed", `${req.method} /v1/chat/completions`);

	let body: ChatCompletionRequest;
	try {
		body = (await req.json()) as ChatCompletionRequest;
	} catch {
		return jsonError(400, "bad_request", "POST body must be valid JSON");
	}
	if (!Array.isArray(body.messages) || body.messages.length === 0) {
		return jsonError(400, "bad_request", "messages array required");
	}

	const requestedModel = body.model ?? cfg.models[0]!;
	const image = resolveModel(cfg, requestedModel);
	if (!image) {
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

	if (body.stream === true) {
		// Streaming SSE. We can't use `pool.withClient` here because the
		// stream outlives this function — manually acquire + release
		// inside the SSE wrapper's cancel/done branches.
		let client: KawiriClient;
		try {
			client = await pool.acquire(image);
		} catch (e) {
			return jsonError(502, "tunnel_unavailable", e instanceof Error ? e.message : String(e));
		}
		const tokenStream = client.chatStream(body.messages, image, options);
		const sse = renderSse(tokenStream, chatId, created, requestedModel, () => pool.release(image));
		return new Response(sse, {
			status: 200,
			headers: {
				"content-type": "text/event-stream",
				"cache-control": "no-cache, no-transform",
				connection: "keep-alive",
				"x-accel-buffering": "no",
			},
		});
	}

	// Non-streaming: aggregate via `chat()`. withClient's finally
	// handles release on both success and error.
	try {
		return await pool.withClient(image, async (client) => {
			const result = await client.chat(body.messages!, image, options);
			return Response.json({
				id: chatId,
				object: "chat.completion",
				created,
				model: requestedModel,
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
		});
	} catch (e) {
		return jsonError(502, "upstream_error", e instanceof Error ? e.message : String(e));
	}
}

/** Generic forwarder for `/v1/*` routes the proxy doesn't reshape
 *  (embeddings, completions, audio, images, …). Returns whatever the
 *  upstream engine emitted: status, JSON body. */
async function handleGenericV1(req: Request, cfg: ServeConfig, pool: ClientPool): Promise<Response> {
	if (req.method !== "GET" && req.method !== "POST") {
		return jsonError(405, "method_not_allowed", `${req.method} ${new URL(req.url).pathname}`);
	}

	// Try to read a model hint from the body (most non-chat OpenAI
	// endpoints take one, e.g. /v1/embeddings has {model, input}). If
	// absent, fall back to the default image. If the body isn't valid
	// JSON, forward as null — endpoints that don't take a body (GET)
	// don't care.
	let parsedBody: unknown = undefined;
	if (req.method === "POST") {
		const text = await req.text();
		if (text.length > 0) {
			try {
				parsedBody = JSON.parse(text);
			} catch {
				return jsonError(400, "bad_request", "POST body must be valid JSON");
			}
		}
	}
	const modelHint =
		parsedBody && typeof parsedBody === "object" && "model" in parsedBody
			? String((parsedBody as { model: unknown }).model ?? "")
			: "";
	const image = modelHint ? resolveModel(cfg, modelHint) : cfg.models[0]!;
	if (!image) {
		return jsonError(404, "model_not_found", `model '${modelHint}' not configured on this proxy`);
	}

	const path = new URL(req.url).pathname;
	try {
		return await pool.withClient(image, async (client) => {
			const upstream = await client.requestRaw(req.method as "GET" | "POST", path, parsedBody);
			return new Response(JSON.stringify(upstream.body ?? null), {
				status: upstream.status || 200,
				headers: { "content-type": "application/json" },
			});
		});
	} catch (e) {
		return jsonError(502, "upstream_error", e instanceof Error ? e.message : String(e));
	}
}

// ── helpers ──────────────────────────────────────────────────────

function resolveModel(cfg: ServeConfig, requested: string): string | null {
	if (cfg.aliases[requested]) return cfg.aliases[requested]!;
	if (cfg.models.includes(requested)) return requested;
	return null;
}

function enforceLocalToken(cfg: ServeConfig, req: Request): Response | null {
	if (!cfg.local_token) return null;
	const provided = (req.headers.get("Authorization") ?? "").replace(/^Bearer\s+/i, "");
	// `timingSafeEqual` requires equal-length buffers; pre-check the
	// length so a wrong-length token doesn't throw on the compare.
	// On length mismatch we still call timingSafeEqual on dummy data
	// to keep the failure path's timing similar.
	const expected = cfg.local_token;
	const a = Buffer.from(provided.padEnd(expected.length, "\0").slice(0, expected.length));
	const b = Buffer.from(expected);
	const sameLength = provided.length === expected.length;
	const sameBytes = timingSafeEqual(a, b);
	if (!sameLength || !sameBytes) {
		return jsonError(401, "unauthorized", "inbound bearer does not match local_token");
	}
	return null;
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
 * Errors mid-stream surface as a chunk with `finish_reason = "error"`
 * plus a final [DONE] so the client closes cleanly rather than
 * hanging on a dropped connection.
 *
 * The `onClose` callback fires when the stream terminates (any
 * reason — done, error, or client-side cancel). It's how the chat
 * handler releases the pool entry so eviction counts can drain.
 */
export function renderSse(
	tokens: ReadableStream<string>,
	chatId: string,
	created: number,
	model: string,
	onClose?: () => void,
): ReadableStream<Uint8Array> {
	const enc = new TextEncoder();
	const reader = tokens.getReader();

	let closeFired = false;
	const fireClose = () => {
		if (closeFired) return;
		closeFired = true;
		onClose?.();
	};

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
				c.enqueue(
					enc.encode(
						sseChunk(chatId, created, model, { content: `\n\n[stream error: ${msg}]` }, "error"),
					),
				);
				c.enqueue(enc.encode("data: [DONE]\n\n"));
			} finally {
				c.close();
				reader.releaseLock();
				fireClose();
			}
		},
		cancel() {
			reader.cancel().catch(() => {});
			fireClose();
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

/** OpenAI-shaped error responses. Standardized so every failure path
 *  comes back as `{ "error": { "code", "message" } }`. */
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
	console.log(`  models:    ${cfg.models.join(", ")}`);
	console.log(`  bind:      ${cfg.bind}:${cfg.port}`);
	console.log(`  api_key:   ${cfg.api_key.slice(0, 6)}…${cfg.api_key.slice(-4)} (${cfg.api_key.length} chars)`);
	console.log(`  pq:        ${cfg.enable_pq ? "on" : "off"}`);
	console.log(`  mock_att:  ${cfg.allow_mock_attestation ? "ALLOWED (INSECURE)" : "off"}`);
	console.log(`  local_tok: ${cfg.local_token ? "set" : "not set"}`);
	console.log(`  idle_evict: ${cfg.idle_close_ms ? `${cfg.idle_close_ms}ms` : "off"}`);
	if (Object.keys(cfg.aliases).length > 0) {
		console.log("  aliases:");
		for (const [from, to] of Object.entries(cfg.aliases)) {
			console.log(`    ${from} → ${to}`);
		}
	}
}
