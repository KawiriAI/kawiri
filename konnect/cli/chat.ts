/**
 * `konnect chat` — one-shot CLI chat.
 *
 *   konnect chat --message "what is the airspeed of a swallow?"
 *   echo "summarize this" | konnect chat        # reads stdin if no --message
 *
 * Streams tokens to stdout as they arrive. Mostly a smoke-test and
 * a "pipe stdin → LLM → stdout" pipeline primitive; not a substitute
 * for the full SSE API exposed by `konnect serve`.
 *
 * Reuses the same config layering as `serve` so one setup drives
 * both. The first model in `models` is used.
 */
import { parseArgs as parseServeArgs, resolveConfig, type RawArgs } from "./config.ts";
import { KattValidator, KawiriClient } from "../core/mod.ts";
import { appendModelToUrl } from "./pool.ts";

const USAGE = `Usage: konnect chat [options]

Sends a one-shot user message and streams the assistant reply to stdout.
The message comes from --message <text>, or from stdin if --message is
not supplied (useful for piping).

Chat-specific options:
  --message <text>         User prompt. If omitted, read from stdin.
  --system <text>          Optional system prompt. Prepended to messages.
  --temperature <n>        Sampling temperature (default: 0.7)
  --max-tokens <n>         Output cap (default: 1024)

All 'konnect serve' configuration options are also accepted (--config,
--api-key, --models, --target, --allow-mock, etc.). --port and --bind
are ignored.
`;

interface ChatArgs {
	message?: string;
	system?: string;
	temperature?: number;
	max_tokens?: number;
}

/** Pull the chat-specific flags out of argv, leaving the rest for
 *  `parseServeArgs` to handle. */
function splitChatArgs(argv: readonly string[]): { chatArgs: ChatArgs; serveArgv: string[] } {
	const chatArgs: ChatArgs = {};
	const serveArgv: string[] = [];
	for (let i = 0; i < argv.length; i++) {
		const a = argv[i]!;
		const next = (): string => {
			const v = argv[++i];
			if (v == null) throw new Error(`${a} requires a value`);
			return v;
		};
		switch (a) {
			case "--message":
				chatArgs.message = next();
				break;
			case "--system":
				chatArgs.system = next();
				break;
			case "--temperature": {
				const t = Number(next());
				if (!Number.isFinite(t) || t < 0) throw new Error("--temperature must be ≥ 0");
				chatArgs.temperature = t;
				break;
			}
			case "--max-tokens": {
				const n = Number(next());
				if (!Number.isInteger(n) || n < 1) throw new Error("--max-tokens must be a positive integer");
				chatArgs.max_tokens = n;
				break;
			}
			default:
				serveArgv.push(a);
				// Multi-arg flags need their value preserved.
				if (
					a.startsWith("--") &&
					a !== "--allow-mock" &&
					a !== "--no-pq" &&
					a !== "--help" &&
					a !== "-h" &&
					a !== "--yes" &&
					a !== "-y"
				) {
					const v = argv[++i];
					if (v != null) serveArgv.push(v);
				}
				break;
		}
	}
	return { chatArgs, serveArgv };
}

async function readStdin(): Promise<string> {
	const chunks: Uint8Array[] = [];
	const reader = (process.stdin as unknown as { stream?: () => ReadableStream<Uint8Array> }).stream?.();
	if (reader) {
		const r = reader.getReader();
		while (true) {
			const { value, done } = await r.read();
			if (done) break;
			if (value) chunks.push(value);
		}
	} else {
		// Fallback path for non-Bun runtimes.
		for await (const chunk of process.stdin) {
			chunks.push(typeof chunk === "string" ? new TextEncoder().encode(chunk) : (chunk as Uint8Array));
		}
	}
	const total = chunks.reduce((n, c) => n + c.byteLength, 0);
	const out = new Uint8Array(total);
	let off = 0;
	for (const c of chunks) {
		out.set(c, off);
		off += c.byteLength;
	}
	return new TextDecoder().decode(out).trim();
}

export async function chatCmd(argv: readonly string[]): Promise<number> {
	if (argv.includes("-h") || argv.includes("--help")) {
		process.stdout.write(USAGE);
		return 0;
	}

	let chatArgs: ChatArgs;
	let serveArgv: string[];
	let rawArgs: RawArgs;
	try {
		const split = splitChatArgs(argv);
		chatArgs = split.chatArgs;
		serveArgv = split.serveArgv;
		rawArgs = parseServeArgs(serveArgv);
	} catch (e) {
		process.stderr.write(`konnect chat: ${e instanceof Error ? e.message : String(e)}\n`);
		return 2;
	}

	let cfg;
	try {
		cfg = await resolveConfig(rawArgs, process.env);
	} catch (e) {
		process.stderr.write(`konnect chat: ${e instanceof Error ? e.message : String(e)}\n`);
		return 2;
	}

	const userMessage = chatArgs.message ?? (await readStdin());
	if (!userMessage) {
		process.stderr.write("konnect chat: no message (pass --message <text> or pipe text to stdin)\n");
		return 2;
	}

	const messages = [
		...(chatArgs.system ? [{ role: "system" as const, content: chatArgs.system }] : []),
		{ role: "user" as const, content: userMessage },
	];

	const image = cfg.models[0]!;
	const validator = new KattValidator({
		allowMock: cfg.allow_mock_attestation,
		liveCollateral: true,
	});
	const client = new KawiriClient({
		url: appendModelToUrl(cfg.target, image),
		validator,
		enablePQ: cfg.enable_pq,
		debug: false,
		webSocketFactory: (u) => {
			const opts = { headers: { Authorization: `Bearer ${cfg.api_key}` } } as unknown as string[];
			return new WebSocket(u, opts);
		},
	});

	try {
		await client.connect();
	} catch (e) {
		process.stderr.write(`konnect chat: tunnel: ${e instanceof Error ? e.message : String(e)}\n`);
		return 1;
	}

	try {
		const stream = client.chatStream(messages, image, {
			temperature: chatArgs.temperature ?? 0.7,
			max_tokens: chatArgs.max_tokens ?? 1024,
		});
		const reader = stream.getReader();
		while (true) {
			const { value, done } = await reader.read();
			if (done) break;
			process.stdout.write(value);
		}
		process.stdout.write("\n");
		return 0;
	} catch (e) {
		process.stderr.write(`\nkonnect chat: stream error: ${e instanceof Error ? e.message : String(e)}\n`);
		return 1;
	} finally {
		try {
			client.close();
		} catch {
			/* swallow */
		}
	}
}
