import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import type { KawiriClient, RawResponse } from "../../core/mod.ts";
import { ClientPool, type PoolOptions } from "../pool.ts";

/**
 * The real KawiriClient does a full Noise + attestation + X-Wing
 * handshake over a real WebSocket. We can't exercise that from unit
 * tests, so we stub the client surface ClientPool actually touches:
 *   - new client per image (factory hook)
 *   - .connect() (called once)
 *   - .requestRaw("GET", "/ping") (liveness probe)
 *   - .close()
 *   - onDisconnect option (so we can simulate a server-side close)
 *
 * The stub is minimal-shape — just enough to look like a KawiriClient
 * to the pool. It records how many connects/probes/closes happened
 * so tests can assert on them.
 */
class FakeClient {
	connectCalls = 0;
	probeCalls = 0;
	closeCalls = 0;
	connectError: Error | null = null;
	probeBehavior: "ok" | "hang" | "error" = "ok";
	probeDelayMs = 0;
	onDisconnect: ((reason: string) => void) | undefined;

	async connect(): Promise<void> {
		this.connectCalls++;
		if (this.connectError) throw this.connectError;
	}
	async requestRaw(_method: string, _path: string): Promise<RawResponse> {
		this.probeCalls++;
		if (this.probeDelayMs > 0) await new Promise((r) => setTimeout(r, this.probeDelayMs));
		if (this.probeBehavior === "error") throw new Error("probe error");
		if (this.probeBehavior === "hang") await new Promise(() => {});
		return { status: 200, body: { ok: true } };
	}
	close(): void {
		this.closeCalls++;
	}
}

function makePool(
	overrides: Partial<PoolOptions> = {},
	clientForImage?: (image: string, fake: FakeClient) => void,
): { pool: ClientPool; fakes: Map<string, FakeClient>; history: FakeClient[] } {
	const fakes = new Map<string, FakeClient>(); // most-recent per image
	const history: FakeClient[] = []; // chronological log across re-opens
	const opts: PoolOptions = {
		target: "wss://test.invalid/v1/chat",
		bearer: "kw_test",
		allowedImages: new Set(["a", "b", "c"]),
		enablePQ: false,
		allowMockAttestation: true,
		idleCloseMs: 0,
		livenessProbeAfterMs: 0,
		livenessProbeTimeoutMs: 1000,
		...overrides,
	};
	const pool = new ClientPool(opts, (image) => {
		const fake = new FakeClient();
		clientForImage?.(image, fake);
		fakes.set(image, fake);
		history.push(fake);
		return fake as unknown as KawiriClient;
	});
	return { pool, fakes, history };
}

describe("ClientPool", () => {
	let pool: ClientPool;

	afterEach(async () => {
		if (pool) await pool.closeAll();
	});

	test("acquire opens one client and reuses it", async () => {
		const { pool: p, fakes } = makePool();
		pool = p;
		const c1 = await pool.acquire("a");
		const c2 = await pool.acquire("a");
		expect(c1).toBe(c2);
		expect(fakes.get("a")!.connectCalls).toBe(1);
		expect(pool.size()).toBe(1);
	});

	test("acquire opens distinct clients per image", async () => {
		const { pool: p, fakes } = makePool();
		pool = p;
		await pool.acquire("a");
		await pool.acquire("b");
		expect(fakes.size).toBe(2);
		expect(fakes.get("a")!.connectCalls).toBe(1);
		expect(fakes.get("b")!.connectCalls).toBe(1);
		expect(pool.size()).toBe(2);
	});

	test("concurrent acquires for same image share one handshake", async () => {
		const { pool: p, fakes } = makePool({}, (_image, fake) => {
			// Make the connect slow so the second acquire genuinely races.
			const original = fake.connect.bind(fake);
			fake.connect = async () => {
				await new Promise((r) => setTimeout(r, 30));
				return original();
			};
		});
		pool = p;
		const [c1, c2, c3] = await Promise.all([
			pool.acquire("a"),
			pool.acquire("a"),
			pool.acquire("a"),
		]);
		expect(c1).toBe(c2);
		expect(c2).toBe(c3);
		expect(fakes.get("a")!.connectCalls).toBe(1);
	});

	test("acquire rejects images not in the allow-list", async () => {
		const { pool: p } = makePool();
		pool = p;
		await expect(pool.acquire("nope")).rejects.toThrow(/not in allowed-models list/);
	});

	test("failed initial connect leaves the pool empty (next acquire retries clean)", async () => {
		const { pool: p, fakes } = makePool({}, (_image, fake) => {
			fake.connectError = new Error("auth rejected");
		});
		pool = p;
		await expect(pool.acquire("a")).rejects.toThrow(/auth rejected/);
		expect(pool.size()).toBe(0);
		// Second attempt: wire a fresh fake without the error.
		const { pool: p2, fakes: fakes2 } = makePool();
		pool = p2;
		await pool.acquire("a");
		expect(fakes2.get("a")!.connectCalls).toBe(1);
		expect(pool.size()).toBe(1);
	});

	test("release decrements in-flight; multiple releases don't go negative", async () => {
		const { pool: p } = makePool();
		pool = p;
		await pool.acquire("a");
		expect(pool.stats()[0]!.inFlight).toBe(1);
		pool.release("a");
		expect(pool.stats()[0]!.inFlight).toBe(0);
		pool.release("a"); // extra release — must not underflow
		expect(pool.stats()[0]!.inFlight).toBe(0);
	});

	test("withClient releases on both success and exception", async () => {
		const { pool: p } = makePool();
		pool = p;
		await pool.withClient("a", async () => "ok");
		expect(pool.stats()[0]!.inFlight).toBe(0);
		await expect(
			pool.withClient("a", async () => {
				throw new Error("boom");
			}),
		).rejects.toThrow("boom");
		expect(pool.stats()[0]!.inFlight).toBe(0);
	});

	test("liveness probe runs after the configured staleness window", async () => {
		const { pool: p, fakes } = makePool({ livenessProbeAfterMs: 0 });
		pool = p;
		// First acquire — no probe (no prior client to probe).
		await pool.withClient("a", async () => {});
		expect(fakes.get("a")!.probeCalls).toBe(0);
		// Second acquire on existing client — probes because age ≥ 0.
		await pool.withClient("a", async () => {});
		expect(fakes.get("a")!.probeCalls).toBe(1);
	});

	test("liveness probe failure evicts and a fresh client is opened", async () => {
		const { pool: p, fakes, history } = makePool({ livenessProbeAfterMs: 0 });
		pool = p;
		await pool.withClient("a", async () => {});
		const first = fakes.get("a")!;
		first.probeBehavior = "error";

		await pool.withClient("a", async () => {});
		// Pool count is 1 (the new one), but two FakeClients have been
		// created in total — the original was closed.
		expect(pool.size()).toBe(1);
		expect(history.length).toBe(2);
		expect(first.closeCalls).toBe(1);
	});

	test("liveness probe timeout evicts (zombie-OPEN socket scenario)", async () => {
		const { pool: p, fakes, history } = makePool({
			livenessProbeAfterMs: 0,
			livenessProbeTimeoutMs: 30,
		});
		pool = p;
		await pool.withClient("a", async () => {});
		const first = fakes.get("a")!;
		first.probeBehavior = "hang";
		// Should time out and evict, then open a fresh one.
		await pool.withClient("a", async () => {});
		expect(history.length).toBe(2);
		expect(first.closeCalls).toBe(1);
	});

	test("closeAll closes every client and clears the map", async () => {
		const { pool: p, fakes } = makePool();
		pool = p;
		await pool.acquire("a");
		await pool.acquire("b");
		pool.release("a");
		pool.release("b");
		await pool.closeAll();
		expect(pool.size()).toBe(0);
		expect(fakes.get("a")!.closeCalls).toBe(1);
		expect(fakes.get("b")!.closeCalls).toBe(1);
		// Subsequent calls are no-ops.
		await pool.closeAll();
	});

	test("post-closeAll acquire throws", async () => {
		const { pool: p } = makePool();
		pool = p;
		await pool.closeAll();
		await expect(pool.acquire("a")).rejects.toThrow(/closed/);
	});
});
