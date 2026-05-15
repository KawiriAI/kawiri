import { describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { parseArgs, resolveConfig } from "../config.ts";

async function withTempFile<T>(content: string, fn: (p: string) => Promise<T>): Promise<T> {
	const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "konnect-test-"));
	const file = path.join(tmp, "config.toml");
	await fs.writeFile(file, content, "utf8");
	try {
		return await fn(file);
	} finally {
		await fs.rm(tmp, { recursive: true, force: true });
	}
}

describe("parseArgs", () => {
	test("simple flags", () => {
		const a = parseArgs([
			"--api-key",
			"kw_abc",
			"--model",
			"qwen-0.6b",
			"--port",
			"9000",
			"--no-pq",
		]);
		expect(a.api_key).toBe("kw_abc");
		expect(a.model).toBe("qwen-0.6b");
		expect(a.port).toBe(9000);
		expect(a.no_pq).toBe(true);
	});

	test("invalid port rejected", () => {
		expect(() => parseArgs(["--port", "abc"])).toThrow();
		expect(() => parseArgs(["--port", "0"])).toThrow();
		expect(() => parseArgs(["--port", "100000"])).toThrow();
	});

	test("unknown flag rejected", () => {
		expect(() => parseArgs(["--what"])).toThrow();
	});

	test("flag missing value rejected", () => {
		expect(() => parseArgs(["--api-key"])).toThrow();
	});
});

describe("resolveConfig — layered overrides", () => {
	test("flag > env > file > default", async () => {
		await withTempFile(
			`
api_key = "from-file"
model = "qwen-0.6b"
port = 8000
target = "wss://from-file.example/v1/chat"
`,
			async (file) => {
				const args = parseArgs(["--config", file, "--api-key", "from-flag", "--port", "9000"]);
				const env = {
					KAWIRI_API_KEY: "from-env",
					KONNECT_TARGET: "wss://from-env.example/v1/chat",
				};
				const cfg = await resolveConfig(args, env);
				// flag wins
				expect(cfg.api_key).toBe("from-flag");
				expect(cfg.port).toBe(9000);
				// env wins over file when no flag
				expect(cfg.target).toBe("wss://from-env.example/v1/chat");
				// file when no env, no flag
				expect(cfg.model).toBe("qwen-0.6b");
			},
		);
	});

	test("api_key required somewhere", async () => {
		const args = parseArgs(["--model", "qwen"]);
		await expect(resolveConfig(args, {})).rejects.toThrow(/api_key required/);
	});

	test("model required somewhere", async () => {
		const args = parseArgs(["--api-key", "kw_x"]);
		await expect(resolveConfig(args, {})).rejects.toThrow(/model is required/);
	});

	test("api_key_file is read", async () => {
		const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "konnect-key-"));
		const keyFile = path.join(tmp, "key");
		await fs.writeFile(keyFile, "kw_from_file\n", "utf8");
		try {
			const args = parseArgs(["--api-key-file", keyFile, "--model", "qwen"]);
			const cfg = await resolveConfig(args, {});
			expect(cfg.api_key).toBe("kw_from_file");
		} finally {
			await fs.rm(tmp, { recursive: true, force: true });
		}
	});

	test("aliases from config", async () => {
		await withTempFile(
			`
api_key = "kw_x"
model = "qwen-0.6b"

[aliases]
"gpt-4o-mini" = "qwen-0.6b"
"qwen-small" = "qwen-0.6b"
`,
			async (file) => {
				const cfg = await resolveConfig(parseArgs(["--config", file]), {});
				expect(cfg.aliases).toEqual({
					"gpt-4o-mini": "qwen-0.6b",
					"qwen-small": "qwen-0.6b",
				});
			},
		);
	});

	test("local_token from config or env", async () => {
		await withTempFile(
			`
api_key = "kw_x"
model = "qwen"

[security]
local_token = "from-file"
`,
			async (file) => {
				const fromFile = await resolveConfig(parseArgs(["--config", file]), {});
				expect(fromFile.local_token).toBe("from-file");

				const fromEnv = await resolveConfig(parseArgs(["--config", file]), {
					KONNECT_LOCAL_TOKEN: "from-env",
				});
				expect(fromEnv.local_token).toBe("from-env");

				const fromFlag = await resolveConfig(
					parseArgs(["--config", file, "--local-token", "from-flag"]),
					{ KONNECT_LOCAL_TOKEN: "from-env" },
				);
				expect(fromFlag.local_token).toBe("from-flag");
			},
		);
	});

	test("--no-pq overrides config enable_pq=true", async () => {
		await withTempFile(
			`
api_key = "kw_x"
model = "qwen"

[security]
enable_pq = true
`,
			async (file) => {
				const cfg = await resolveConfig(parseArgs(["--config", file, "--no-pq"]), {});
				expect(cfg.enable_pq).toBe(false);
			},
		);
	});

	test("invalid TOML in config file surfaces a clear error", async () => {
		await withTempFile("this is = not valid = toml", async (file) => {
			await expect(resolveConfig(parseArgs(["--config", file]), {})).rejects.toThrow();
		});
	});

	test("missing config file surfaces a clear error", async () => {
		await expect(
			resolveConfig(parseArgs(["--config", "/nonexistent/konnect.toml"]), {}),
		).rejects.toThrow();
	});
});
