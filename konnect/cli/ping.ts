/**
 * `konnect ping` — health-check the tunnel.
 *
 * Connects (Noise + attestation + X-Wing PQ), runs a single `/ping`
 * round-trip over the encrypted channel, prints the result, exits.
 *
 * Useful for CI/monitoring: drop in a probe that exits 0 only when
 * the entire stack — bearer auth, registry dispatch, mTLS to teehost,
 * TEE quote verification, X-Wing handshake, and kawa's in-CVM HTTP
 * server — is alive end-to-end.
 *
 * Reuses the same config layering as `serve` so a single TOML/env/flag
 * setup drives both.
 */
import { parseArgs as parseServeArgs, resolveConfig, type RawArgs } from "./config.ts";
import { KattValidator, KawiriClient } from "../core/mod.ts";
import { appendModelToUrl } from "./pool.ts";

const USAGE = `Usage: konnect ping [options]

Probes the tunnel end-to-end and exits 0 on success, non-zero on
failure. Same options as 'konnect serve' for configuration; --port,
--bind, --aliases, etc. are accepted but ignored.

Exit codes:
  0  tunnel ready, /ping responded
  1  tunnel could not establish (auth, attestation, or transport)
  2  bad arguments / config
`;

export async function pingCmd(argv: readonly string[]): Promise<number> {
	if (argv.includes("-h") || argv.includes("--help")) {
		process.stdout.write(USAGE);
		return 0;
	}

	let rawArgs: RawArgs;
	try {
		rawArgs = parseServeArgs(argv);
	} catch (e) {
		process.stderr.write(`konnect ping: ${e instanceof Error ? e.message : String(e)}\n`);
		return 2;
	}

	let cfg;
	try {
		cfg = await resolveConfig(rawArgs, process.env);
	} catch (e) {
		process.stderr.write(`konnect ping: ${e instanceof Error ? e.message : String(e)}\n`);
		return 2;
	}

	const image = cfg.models[0]!;
	const startMs = performance.now();

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
		const connectMs = performance.now() - startMs;
		const pingStart = performance.now();
		const resp = await client.requestRaw("GET", "/ping");
		const pingMs = performance.now() - pingStart;
		const totalMs = performance.now() - startMs;
		console.log(
			[
				`tunnel:      ${cfg.target}`,
				`model:       ${image}`,
				`mock_att:    ${cfg.allow_mock_attestation ? "yes" : "no"}`,
				`pq:          ${cfg.enable_pq ? "on" : "off"}`,
				"",
				`connect:     ${connectMs.toFixed(1)}ms (Noise + attestation + X-Wing)`,
				`/ping:       ${pingMs.toFixed(1)}ms  status=${resp.status}`,
				`total:       ${totalMs.toFixed(1)}ms`,
				"",
				"ok",
			].join("\n"),
		);
		return 0;
	} catch (e) {
		const msg = e instanceof Error ? e.message : String(e);
		process.stderr.write(`konnect ping: failed: ${msg}\n`);
		return 1;
	} finally {
		try {
			client.close();
		} catch {
			/* swallow */
		}
	}
}
