#!/usr/bin/env bun
/**
 * `konnect` — CLI entry point. Dispatches subcommands.
 *
 *   konnect serve    OpenAI-compatible local proxy in front of the
 *                    Kawiri encrypted+attested tunnel. Local tools
 *                    (OpenWebUI, Continue, Cursor, llm-cli, …) point
 *                    at http://127.0.0.1:8090 and get plain OpenAI
 *                    HTTP semantics; the proxy translates to the
 *                    konnect WS protocol underneath.
 *
 *   konnect chat     One-shot CLI chat. Mostly for smoke-testing,
 *                    pipes stdin → prompt and stdout ← reply.
 *
 *   konnect ping     Connect, attest, run a single /ping. Verifies
 *                    the tunnel is healthy. Exits 0/1.
 *
 *   konnect version  Prints the package version. Useful for CI.
 *
 * The CLI is Bun-only (uses Bun.serve, Bun.file). The browser-safe
 * library at ../core/mod.ts has no runtime dependency on this file
 * — bin scripts are not bundled when consumers `import` the library.
 */
import { serveCmd } from "./serve.ts";

const USAGE = `Usage: konnect <command> [options]

Commands:
  serve     Run the OpenAI-compatible proxy
  chat      Send a one-shot chat (smoke test)
  ping      Probe tunnel liveness; exit 0 on success
  version   Print package version
  help      Show this message

Run "konnect <command> --help" for command-specific options.
`;

async function main(): Promise<number> {
	const args = Bun.argv.slice(2);
	const cmd = args[0];

	if (!cmd || cmd === "help" || cmd === "--help" || cmd === "-h") {
		process.stdout.write(USAGE);
		return 0;
	}

	if (cmd === "version" || cmd === "--version" || cmd === "-V") {
		// Read the colocated package.json so the version is always the
		// installed one — works both from source (./package.json) and
		// from `bun install -g` (the bin is hoisted but the import path
		// still resolves to the package root).
		const pkg = await Bun.file(new URL("../package.json", import.meta.url)).json();
		process.stdout.write(`${pkg.version}\n`);
		return 0;
	}

	const rest = args.slice(1);
	switch (cmd) {
		case "serve":
			return await serveCmd(rest);
		case "chat":
		case "ping":
			process.stderr.write(`konnect: '${cmd}' not yet implemented in v0\n`);
			return 2;
		default:
			process.stderr.write(`konnect: unknown command '${cmd}'\n\n${USAGE}`);
			return 2;
	}
}

const code = await main();
process.exit(code);
