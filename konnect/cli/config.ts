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

	/** All kcvm images this proxy is permitted to open WS connections
	 *  for. First element is the default — used when a request omits
	 *  `model`. Single-element list = single-model proxy (the v0 shape). */
	models: string[];

	// Local HTTP listener.
	bind: string;
	port: number;

	// Security knobs.
	local_token: string | null; // if set, inbound bearer must match
	allow_mock_attestation: boolean; // dev only
	enable_pq: boolean; // X-Wing PQ upgrade

	/** Model aliasing. Map of OpenAI-named model → kcvm image. Every
	 *  alias target MUST appear in `models` (validated). `/v1/models`
	 *  advertises both the configured images and every alias. */
	aliases: Record<string, string>;

	/** Idle eviction window for unused per-image clients (ms). 0
	 *  disables eviction. */
	idle_close_ms: number;
	/** When the last successful request on a client is older than this,
	 *  acquire() runs a /ping first to verify the channel. ms. */
	liveness_probe_after_ms: number;
	/** Per-probe deadline. ms. */
	liveness_probe_timeout_ms: number;
}

const DEFAULTS: Omit<ServeConfig, "api_key" | "models"> = {
	target: "wss://api.kawiri.ai/v1/chat",
	bind: "127.0.0.1",
	port: 8090,
	local_token: null,
	allow_mock_attestation: false,
	enable_pq: true,
	aliases: {},
	idle_close_ms: 10 * 60 * 1000, // 10 minutes
	liveness_probe_after_ms: 30 * 1000, // 30 seconds
	liveness_probe_timeout_ms: 2500,
};

export interface RawArgs {
	config?: string;
	api_key?: string;
	api_key_file?: string;
	target?: string;
	/** `--model`: single model. Sets `models` to `[value]` unless
	 *  `--models` is also passed (in which case `--models` wins). */
	model?: string;
	/** `--models`: CSV list, becomes `models` verbatim. */
	models?: string[];
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
			case "--models": {
				const csv = next();
				const list = csv
					.split(",")
					.map((s) => s.trim())
					.filter((s) => s.length > 0);
				if (list.length === 0) throw new Error("--models must list at least one image");
				out.models = list;
				break;
			}
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
  --model <image>          Default kcvm image. Sets the served list to
                           [<image>] unless --models is also given.
  --models <csv>           Comma-separated list of kcvm images this proxy
                           is permitted to open WS connections for. First
                           entry is the default-when-omitted. Overrides
                           any --model value.
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
  KONNECT_MODELS           Equivalent to --models (CSV)
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

	const models = pickModels(rawArgs, env, fileConfig);

	const target = rawArgs.target ?? env.KONNECT_TARGET ?? fileConfig.target ?? DEFAULTS.target;
	const bind = rawArgs.bind ?? env.KONNECT_BIND ?? fileConfig.bind ?? DEFAULTS.bind;
	const port = pickPort(rawArgs.port, env.KONNECT_PORT, fileConfig.port);
	const local_token = rawArgs.local_token ?? env.KONNECT_LOCAL_TOKEN ?? fileConfig.security?.local_token ?? null;

	const allow_mock_attestation = pickBool(
		rawArgs.allow_mock,
		env.KONNECT_ALLOW_MOCK,
		fileConfig.security?.allow_mock_attestation,
		false,
	);
	const enable_pq =
		rawArgs.no_pq === true
			? false
			: pickBool(undefined, env.KONNECT_ENABLE_PQ, fileConfig.security?.enable_pq, true);

	const aliases: Record<string, string> = { ...(fileConfig.aliases ?? {}) };

	// Every alias target must point at a permitted image — otherwise
	// /v1/models would advertise a model that requests then fail on.
	const allowed = new Set(models);
	for (const [alias, target] of Object.entries(aliases)) {
		if (!allowed.has(target)) {
			throw new Error(
				`alias '${alias}' targets '${target}', which is not in 'models'. ` +
					`Add it to the models list, or drop the alias.`,
			);
		}
	}

	return {
		api_key: apiKey,
		target,
		models,
		bind,
		port,
		local_token: local_token && local_token.length > 0 ? local_token : null,
		allow_mock_attestation,
		enable_pq,
		aliases,
		idle_close_ms: fileConfig.idle_close_ms ?? DEFAULTS.idle_close_ms,
		liveness_probe_after_ms: fileConfig.liveness_probe_after_ms ?? DEFAULTS.liveness_probe_after_ms,
		liveness_probe_timeout_ms: fileConfig.liveness_probe_timeout_ms ?? DEFAULTS.liveness_probe_timeout_ms,
	};
}

/**
 * Resolve the list of permitted kcvm images. Sources (last wins):
 *   1. fileConfig.model (single) → [model]
 *   2. fileConfig.models (array)
 *   3. KONNECT_MODEL (single) → [model]
 *   4. KONNECT_MODELS (csv)
 *   5. rawArgs.model (single) → [model]
 *   6. rawArgs.models (already array)
 *
 * Single-form always becomes a one-element array; array-form is taken
 * verbatim. First element is the default-when-request-omits-model.
 */
function pickModels(rawArgs: RawArgs, env: Record<string, string | undefined>, fileConfig: TomlConfig): string[] {
	if (rawArgs.models && rawArgs.models.length > 0) return rawArgs.models;
	if (rawArgs.model && rawArgs.model.trim().length > 0) return [rawArgs.model.trim()];

	const envCsv = env.KONNECT_MODELS;
	if (envCsv) {
		const list = envCsv
			.split(",")
			.map((s) => s.trim())
			.filter((s) => s.length > 0);
		if (list.length > 0) return list;
	}
	const envSingle = env.KONNECT_MODEL;
	if (envSingle && envSingle.trim().length > 0) return [envSingle.trim()];

	if (fileConfig.models && Array.isArray(fileConfig.models) && fileConfig.models.length > 0) {
		const cleaned = fileConfig.models
			.filter((s): s is string => typeof s === "string")
			.map((s) => s.trim())
			.filter((s) => s.length > 0);
		if (cleaned.length === 0) {
			throw new Error("config 'models' must be a non-empty array of image strings");
		}
		return cleaned;
	}
	if (fileConfig.model && fileConfig.model.trim().length > 0) {
		return [fileConfig.model.trim()];
	}

	throw new Error(
		"at least one model is required (set --model, --models, KONNECT_MODEL, KONNECT_MODELS, or model/models in --config)",
	);
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
	/** Single-image (back-compat with v0.4). Treated as [model] if `models` is unset. */
	model?: string;
	/** Multi-image (v0.5+). First entry is the default. */
	models?: string[];
	bind?: string;
	port?: number;
	idle_close_ms?: number;
	liveness_probe_after_ms?: number;
	liveness_probe_timeout_ms?: number;
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
