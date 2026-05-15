/**
 * Config for `konnect serve`. Three sources, last-write-wins:
 *
 *   1. Built-in defaults.
 *   2. TOML file at --config (or KONNECT_CONFIG env).
 *   3. Env vars (KAWIRI_API_KEY, KONNECT_PORT, …).
 *   4. CLI flags.
 *
 * Each source produces a partial config; they merge top-down so a
 * flag always wins over env, env always wins over file, file always
 * wins over the default. The result is the effective config that
 * `serve.ts` runs against.
 *
 * Why layered over single-source: ops scenarios want a TOML file
 * checked into config management ("the boring case"), dev scenarios
 * want a quick env-var override ("KAWIRI_API_KEY=… konnect serve"),
 * and one-off tests want a CLI flag. Supporting all three at zero
 * cognitive cost is just the right thing.
 */
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { parse as parseToml } from "smol-toml";

export interface ServeConfig {
	// Required.
	api_key: string;

	// Tunnel target — the api.kawiri.ai WS upgrade endpoint.
	target: string;

	// The kcvm image the WS upgrade will be routed to. Single-image
	// per proxy process in v0; aliases let multiple OpenAI model
	// names resolve to this same image.
	model: string;

	// Local HTTP listener.
	bind: string;
	port: number;

	// Security knobs.
	local_token: string | null; // if set, inbound bearer must match
	allow_mock_attestation: boolean; // dev only
	enable_pq: boolean; // X-Wing PQ upgrade

	// Model aliasing. Map of OpenAI-named model → kcvm image. In v0
	// the kcvm image must be the same `model` above; the alias map
	// just tells `/v1/models` which names to advertise.
	aliases: Record<string, string>;
}

const DEFAULTS: Omit<ServeConfig, "api_key" | "model"> = {
	target: "wss://api.kawiri.ai/v1/chat",
	bind: "127.0.0.1",
	port: 8090,
	local_token: null,
	allow_mock_attestation: false,
	enable_pq: true,
	aliases: {},
};

export interface RawArgs {
	config?: string;
	api_key?: string;
	api_key_file?: string;
	target?: string;
	model?: string;
	bind?: string;
	port?: number;
	local_token?: string;
	allow_mock?: boolean;
	no_pq?: boolean;
}

/**
 * Parse `konnect serve` argv. Hand-rolled rather than pulling a flag
 * library — the surface is small and our shape is fixed.
 */
export function parseArgs(argv: readonly string[]): RawArgs {
	const out: RawArgs = {};
	for (let i = 0; i < argv.length; i++) {
		const a = argv[i]!;
		const next = (): string => {
			const v = argv[++i];
			if (v == null) throw new Error(`${a} requires a value`);
			return v;
		};
		switch (a) {
			case "--config":
				out.config = next();
				break;
			case "--api-key":
				out.api_key = next();
				break;
			case "--api-key-file":
				out.api_key_file = next();
				break;
			case "--target":
				out.target = next();
				break;
			case "--model":
				out.model = next();
				break;
			case "--bind":
				out.bind = next();
				break;
			case "--port": {
				const n = Number(next());
				if (!Number.isInteger(n) || n < 1 || n > 65535) {
					throw new Error("--port must be an integer 1..65535");
				}
				out.port = n;
				break;
			}
			case "--local-token":
				out.local_token = next();
				break;
			case "--allow-mock":
				out.allow_mock = true;
				break;
			case "--no-pq":
				out.no_pq = true;
				break;
			case "--help":
			case "-h":
				printServeHelp();
				process.exit(0);
				break;
			default:
				throw new Error(`unknown flag: ${a}`);
		}
	}
	return out;
}

function printServeHelp(): void {
	process.stdout.write(`Usage: konnect serve [options]

Listens on a local HTTP port and exposes an OpenAI-compatible API
that tunnels to Kawiri's encrypted+attested channel underneath.

Options:
  --config <path>          Path to a TOML config file
  --api-key <key>          Kawiri API key (kw_…); overrides config + env
  --api-key-file <path>    Read api_key from a file (mode 0600 expected)
  --target <url>           Tunnel target (default: wss://api.kawiri.ai/v1/chat)
  --model <image>          Default kcvm image (the model the WS routes to)
  --bind <addr>            Listen address (default: 127.0.0.1)
  --port <n>               Listen port (default: 8090)
  --local-token <token>    If set, inbound Authorization must match this
  --allow-mock             Accept mock TEE attestation (dev only — INSECURE)
  --no-pq                  Disable X-Wing post-quantum upgrade (debug)
  -h, --help               Show this message

Env vars:
  KONNECT_CONFIG           Equivalent to --config
  KAWIRI_API_KEY           Equivalent to --api-key
  KAWIRI_API_KEY_FILE      Equivalent to --api-key-file
  KONNECT_TARGET           Equivalent to --target
  KONNECT_MODEL            Equivalent to --model
  KONNECT_BIND             Equivalent to --bind
  KONNECT_PORT             Equivalent to --port
  KONNECT_LOCAL_TOKEN      Equivalent to --local-token

Resolution: CLI flag > env var > config file > default.
`);
}

/**
 * Resolve the effective config. Reads file (if any), env, args; merges
 * with defaults. Throws on anything missing or invalid.
 */
export async function resolveConfig(rawArgs: RawArgs, env: Record<string, string | undefined>): Promise<ServeConfig> {
	// File first — the base layer above defaults.
	const filePath = rawArgs.config ?? env.KONNECT_CONFIG;
	const fileConfig = filePath ? await readTomlConfig(filePath) : {};

	const apiKey = await pickApiKey(rawArgs, env, fileConfig);

	const model = rawArgs.model ?? env.KONNECT_MODEL ?? fileConfig.model;
	if (typeof model !== "string" || !model.trim()) {
		throw new Error("model is required (set --model, KONNECT_MODEL, or [model] in --config)");
	}

	const target = rawArgs.target ?? env.KONNECT_TARGET ?? fileConfig.target ?? DEFAULTS.target;
	const bind = rawArgs.bind ?? env.KONNECT_BIND ?? fileConfig.bind ?? DEFAULTS.bind;
	const port = pickPort(rawArgs.port, env.KONNECT_PORT, fileConfig.port);
	const local_token = rawArgs.local_token ?? env.KONNECT_LOCAL_TOKEN ?? fileConfig.security?.local_token ?? null;

	const allow_mock_attestation = pickBool(rawArgs.allow_mock, env.KONNECT_ALLOW_MOCK, fileConfig.security?.allow_mock_attestation, false);
	const enable_pq = rawArgs.no_pq === true ? false : pickBool(undefined, env.KONNECT_ENABLE_PQ, fileConfig.security?.enable_pq, true);

	const aliases: Record<string, string> = { ...(fileConfig.aliases ?? {}) };

	return {
		api_key: apiKey,
		target,
		model: model.trim(),
		bind,
		port,
		local_token: local_token && local_token.length > 0 ? local_token : null,
		allow_mock_attestation,
		enable_pq,
		aliases,
	};
}

async function pickApiKey(
	rawArgs: RawArgs,
	env: Record<string, string | undefined>,
	fileConfig: TomlConfig,
): Promise<string> {
	// 1. Explicit --api-key flag.
	if (rawArgs.api_key && rawArgs.api_key.length > 0) return rawArgs.api_key;
	// 2. Env var.
	if (env.KAWIRI_API_KEY && env.KAWIRI_API_KEY.length > 0) return env.KAWIRI_API_KEY;
	// 3. --api-key-file flag, env var, or config-file pointer — read the file.
	const filePath = rawArgs.api_key_file ?? env.KAWIRI_API_KEY_FILE ?? fileConfig.api_key_file;
	if (filePath) {
		const buf = await fs.readFile(path.resolve(filePath), "utf8");
		const k = buf.trim();
		if (!k) throw new Error(`api-key-file at ${filePath} is empty`);
		return k;
	}
	// 4. api_key directly in config file.
	if (fileConfig.api_key && fileConfig.api_key.length > 0) return fileConfig.api_key;

	throw new Error(
		"api_key required (set --api-key, KAWIRI_API_KEY env, --api-key-file, or api_key in --config)",
	);
}

function pickPort(argPort: number | undefined, envPort: string | undefined, filePort: number | undefined): number {
	if (argPort != null) return argPort;
	if (envPort != null) {
		const n = Number(envPort);
		if (!Number.isInteger(n) || n < 1 || n > 65535) {
			throw new Error(`KONNECT_PORT must be an integer 1..65535 (got ${envPort})`);
		}
		return n;
	}
	if (filePort != null) {
		if (!Number.isInteger(filePort) || filePort < 1 || filePort > 65535) {
			throw new Error(`config port must be an integer 1..65535 (got ${filePort})`);
		}
		return filePort;
	}
	return DEFAULTS.port;
}

function pickBool(
	argVal: boolean | undefined,
	envVal: string | undefined,
	fileVal: boolean | undefined,
	def: boolean,
): boolean {
	if (argVal != null) return argVal;
	if (envVal != null) {
		const v = envVal.toLowerCase().trim();
		if (v === "1" || v === "true" || v === "yes" || v === "on") return true;
		if (v === "0" || v === "false" || v === "no" || v === "off") return false;
	}
	if (fileVal != null) return fileVal;
	return def;
}

interface TomlConfig {
	api_key?: string;
	api_key_file?: string;
	target?: string;
	model?: string;
	bind?: string;
	port?: number;
	security?: {
		local_token?: string;
		allow_mock_attestation?: boolean;
		enable_pq?: boolean;
	};
	aliases?: Record<string, string>;
}

async function readTomlConfig(filePath: string): Promise<TomlConfig> {
	const raw = await fs.readFile(path.resolve(filePath), "utf8");
	const parsed = parseToml(raw) as TomlConfig;
	if (typeof parsed !== "object" || parsed === null) {
		throw new Error(`config at ${filePath} is not a TOML table`);
	}
	return parsed;
}
