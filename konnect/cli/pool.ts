/**
 * `ClientPool` — one KawiriClient per kcvm image, keyed by image
 * identifier. Each `acquire(image)` returns a live, attested, X-Wing-
 * upgraded client; concurrent callers for the same image share a
 * single in-flight handshake.
 *
 * Why per-image: the router pins a model at WS-upgrade time
 * (`?model=<image>`), so every request on a given WS routes to the
 * same VM. Serving multiple models from one proxy process requires
 * multiple WS connections — all authenticated with the same bearer.
 *
 * Lifecycle:
 *   * Lazy open on first `acquire(image)`. Avoids paying the Noise +
 *     attestation + X-Wing cost for models nobody asks for.
 *   * Liveness probe (`/ping`) before reuse when last successful
 *     interaction is older than `livenessProbeAfterMs`. Detects
 *     half-closed sockets that haven't yet emitted `onclose`.
 *   * Idle eviction: a ticker closes clients that haven't been
 *     touched in `idleCloseMs`. Skipped when `inFlight > 0` so
 *     long-running streams aren't yanked out from under their
 *     consumers.
 *   * `onclose` from the underlying WS drops the entry from the map;
 *     the next `acquire` opens a fresh one.
 *   * `closeAll()` for SIGINT shutdown — sends `1000 Normal Closure`
 *     to every WS, drops the map, stops the eviction ticker.
 *
 * Failures are surfaced to the caller, not buried: if attestation
 * doesn't verify or the bearer is rejected, `acquire()` throws and
 * the entry is removed so the next attempt isn't poisoned.
 */
import { type AttestationValidator, KattValidator, KawiriClient, type RawResponse } from "../core/mod.ts";

export interface PoolOptions {
	/** Tunnel target, e.g. `wss://api.kawiri.ai/v1/chat`. */
	target: string;
	/** Bearer to inject as `Authorization` on every WS upgrade. */
	bearer: string;
	/** Set of kcvm images the pool is permitted to open. Requests
	 *  for images outside this set are rejected at the proxy edge,
	 *  not here. */
	allowedImages: ReadonlySet<string>;
	enablePQ: boolean;
	allowMockAttestation: boolean;

	/** Close clients idle longer than this. 0 disables eviction. */
	idleCloseMs: number;
	/** On `acquire`, run a `/ping` first if the last successful
	 *  interaction is older than this. Catches half-closed sockets
	 *  that didn't emit onclose. 0 disables (every acquire probes). */
	livenessProbeAfterMs: number;
	/** Per-probe timeout. */
	livenessProbeTimeoutMs: number;

	/** Hook called whenever a client finishes its handshake +
	 *  attestation. Used by `serve` for log output. */
	onClientReady?: (image: string) => void;
	/** Hook called whenever a client leaves the pool, with reason. */
	onClientClosed?: (image: string, reason: string) => void;
}

interface PoolEntry {
	client: KawiriClient;
	lastSuccessAt: number;
	/** Non-null while the initial handshake is in flight. Concurrent
	 *  acquires await this promise instead of opening a duplicate WS. */
	connecting: Promise<void> | null;
	/** Refcount of in-flight requests using this client. Eviction
	 *  skips entries with `inFlight > 0`. */
	inFlight: number;
}

export class ClientPool {
	private readonly entries = new Map<string, PoolEntry>();
	private evictTimer: ReturnType<typeof setInterval> | null = null;
	private closed = false;
	private readonly factory: (image: string) => KawiriClient;

	constructor(
		private readonly opts: PoolOptions,
		factoryOverride?: (image: string) => KawiriClient,
	) {
		this.factory = factoryOverride ?? ((image) => this.defaultFactory(image));
		if (opts.idleCloseMs > 0) {
			// Tick at one-quarter of the idle window — granular enough that
			// stale clients leave promptly without burning a wakeup every
			// second.
			const tickMs = Math.max(1000, Math.floor(opts.idleCloseMs / 4));
			this.evictTimer = setInterval(() => this.evictIdle(), tickMs);
		}
	}

	/**
	 * Get a live client for `image`. Opens lazily if not present,
	 * runs a liveness probe if stale, retries fresh on probe failure.
	 *
	 * Caller MUST call `release(image)` after the request finishes
	 * (success OR failure) so the inFlight counter stays accurate.
	 * `withClient` below packages that as a try/finally.
	 */
	async acquire(image: string): Promise<KawiriClient> {
		if (this.closed) throw new Error("ClientPool closed");
		if (!this.opts.allowedImages.has(image)) {
			throw new Error(`image not in allowed-models list: ${image}`);
		}

		let entry = this.entries.get(image);

		if (entry) {
			// Wait for any in-flight handshake.
			if (entry.connecting) {
				try {
					await entry.connecting;
				} catch (e) {
					// Initial connect failed; entry was already removed.
					throw e;
				}
				entry = this.entries.get(image);
				if (!entry) {
					// Removed mid-connect by onclose / failure. Open fresh.
					return await this.acquire(image);
				}
			}
			// Liveness probe — skip when in-flight requests prove the
			// channel is currently alive.
			if (entry.inFlight === 0 && this.needsProbe(entry)) {
				const alive = await this.probeLiveness(entry.client);
				if (!alive) {
					this.evict(image, "liveness probe failed");
					return await this.acquire(image);
				}
				entry.lastSuccessAt = Date.now();
			}
			entry.inFlight++;
			return entry.client;
		}

		// First touch for this image — open and atomically register
		// the entry so concurrent acquires await one handshake.
		const client = this.factory(image);
		const connecting = (async () => {
			try {
				await client.connect();
				this.opts.onClientReady?.(image);
			} catch (e) {
				// Failed handshake → drop the placeholder so the next
				// attempt opens cleanly.
				this.entries.delete(image);
				try {
					client.close();
				} catch {
					/* swallow */
				}
				throw e;
			}
		})();
		const fresh: PoolEntry = {
			client,
			lastSuccessAt: Date.now(),
			connecting,
			inFlight: 0,
		};
		this.entries.set(image, fresh);
		await connecting;
		fresh.connecting = null;
		fresh.inFlight = 1;
		return fresh.client;
	}

	/** Call once the request that called `acquire(image)` has finished
	 *  (success OR failure). Decrements the in-flight counter so idle
	 *  eviction can reap when appropriate. */
	release(image: string): void {
		const entry = this.entries.get(image);
		if (!entry) return;
		if (entry.inFlight > 0) entry.inFlight--;
		entry.lastSuccessAt = Date.now();
	}

	/** Bump the entry's "last success" timestamp without changing
	 *  the in-flight refcount. Called per token during a long stream
	 *  so idle eviction doesn't fire mid-generation if a future bug
	 *  somehow leaves `inFlight === 0` while bytes are still flowing.
	 *  Cheap (one Map lookup + one assignment) and bug-free no-op
	 *  when the entry has already been evicted. */
	touchLastSuccess(image: string): void {
		const entry = this.entries.get(image);
		if (!entry) return;
		entry.lastSuccessAt = Date.now();
	}

	/** Convenience wrapper: acquire → run fn → release, with the
	 *  release fired in `finally`. Safe even if `fn` throws. */
	async withClient<T>(image: string, fn: (client: KawiriClient) => Promise<T>): Promise<T> {
		const client = await this.acquire(image);
		try {
			return await fn(client);
		} finally {
			this.release(image);
		}
	}

	/** Number of currently-open clients. Mostly for `/readyz` and
	 *  log lines. */
	size(): number {
		return this.entries.size;
	}

	/** Snapshot of (image, inFlight, idleMs) for `/readyz` reporting
	 *  and tests. */
	stats(): { image: string; inFlight: number; idleMs: number }[] {
		const now = Date.now();
		return Array.from(this.entries.entries()).map(([image, e]) => ({
			image,
			inFlight: e.inFlight,
			idleMs: now - e.lastSuccessAt,
		}));
	}

	/** Close every client and stop the eviction ticker. Safe to call
	 *  multiple times. */
	async closeAll(): Promise<void> {
		if (this.closed) return;
		this.closed = true;
		if (this.evictTimer) {
			clearInterval(this.evictTimer);
			this.evictTimer = null;
		}
		for (const [image, entry] of this.entries.entries()) {
			try {
				entry.client.close();
			} catch {
				/* swallow — best-effort shutdown */
			}
			this.opts.onClientClosed?.(image, "pool shutdown");
		}
		this.entries.clear();
	}

	// ── internals ───────────────────────────────────────────────

	private needsProbe(entry: PoolEntry): boolean {
		if (this.opts.livenessProbeAfterMs <= 0) return true;
		return Date.now() - entry.lastSuccessAt >= this.opts.livenessProbeAfterMs;
	}

	private async probeLiveness(client: KawiriClient): Promise<boolean> {
		const timeoutMs = this.opts.livenessProbeTimeoutMs;
		const probe = client.requestRaw("GET", "/ping").then(
			() => true,
			() => false,
		);
		// Race against a wall-clock timeout — iOS-style zombie sockets
		// manifest as "send never errors and never resolves," so error
		// handling alone isn't enough; we need a positive deadline.
		const timeout = new Promise<boolean>((r) => setTimeout(() => r(false), timeoutMs));
		return await Promise.race([probe, timeout]);
	}

	private evictIdle(): void {
		if (this.closed) return;
		const now = Date.now();
		const cutoff = now - this.opts.idleCloseMs;
		for (const [image, entry] of this.entries.entries()) {
			if (entry.inFlight > 0) continue;
			if (entry.connecting) continue;
			if (entry.lastSuccessAt > cutoff) continue;
			this.evict(image, "idle eviction");
		}
	}

	private evict(image: string, reason: string): void {
		const entry = this.entries.get(image);
		if (!entry) return;
		this.entries.delete(image);
		try {
			entry.client.close();
		} catch {
			/* swallow */
		}
		this.opts.onClientClosed?.(image, reason);
	}

	private defaultFactory(image: string): KawiriClient {
		const validator: AttestationValidator = new KattValidator({
			allowMock: this.opts.allowMockAttestation,
			liveCollateral: true,
		});
		const url = appendModelToUrl(this.opts.target, image);
		const bearer = this.opts.bearer;
		const client = new KawiriClient({
			url,
			validator,
			enablePQ: this.opts.enablePQ,
			debug: false,
			webSocketFactory: (u) => wsWithBearer(u, bearer),
			onDisconnect: (reason) => {
				// Drop the entry on disconnect so the next acquire opens
				// fresh. Don't call close() — the WS is already closed.
				if (this.entries.has(image)) {
					this.entries.delete(image);
					this.opts.onClientClosed?.(image, reason);
				}
			},
		});
		return client;
	}
}

/** Append `?model=<image>` to the WS URL, preserving any existing
 *  query. The router reads this on the WS upgrade to decide which
 *  VM dispatch picks. */
export function appendModelToUrl(url: string, model: string): string {
	try {
		const u = new URL(url);
		u.searchParams.set("model", model);
		return u.toString();
	} catch {
		const sep = url.includes("?") ? "&" : "?";
		return `${url}${sep}model=${encodeURIComponent(model)}`;
	}
}

/** Construct a WebSocket carrying an `Authorization: Bearer …` header.
 *  Bun/Node accept the options-bag second arg; the cast suppresses the
 *  browser-flavored DOM typing that thinks the second arg is `string[]`. */
function wsWithBearer(url: string, bearer: string): WebSocket {
	const opts = { headers: { Authorization: `Bearer ${bearer}` } } as unknown as string[];
	return new WebSocket(url, opts);
}
