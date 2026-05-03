import type { KawiriClient } from "@kawiri/konnect";

interface PooledClient {
  client: KawiriClient;
  bornAt: number;
}

export interface WarmPoolOptions {
  /** Target depth — pool refills toward this number async on every take(). */
  targetSize: number;
  /** Transports older than this are discarded and replaced. */
  maxAgeMs: number;
  /** Build a fresh, fully-attested + (optionally) X-Wing'd client. */
  factory: () => Promise<KawiriClient>;
  /** Called when a background refill fails — do not crash the proxy. */
  onError?: (err: Error) => void;
}

/**
 * Pool of pre-handshaked KawiriClients. Each entry has finished Noise XX +
 * attestation + X-Wing but has NOT yet sent `tunnel.open` — taking one and
 * calling openTunnel() is one round-trip, not a full ~1s handshake.
 *
 * Why a pool: a SSH-CVM workflow typically opens many short transports
 * (`scp`, `rsync`, parallel `ssh` sessions), and re-attesting each one
 * makes the UX miserable. The pool amortizes attestation cost.
 *
 * Eviction: transports older than maxAgeMs are dropped on the next take()
 * so we don't keep hour-old encrypted transports around. This is hygiene —
 * the cipher state itself is fine sitting idle.
 */
export class WarmPool {
  private clients: PooledClient[] = [];
  private connecting = 0;
  private closed = false;

  constructor(private opts: WarmPoolOptions) {
    this.refill();
  }

  /** Pop a warm client (or kick off a synchronous handshake if pool empty). */
  async take(): Promise<KawiriClient> {
    this.expireStale();

    const ready = this.clients.shift();
    if (ready) {
      // Fire-and-forget refill so the next take() finds a warm one.
      this.refill();
      return ready.client;
    }

    // Pool empty: do a fresh handshake right now (slow path) and still
    // refill in the background so subsequent takes are warm again.
    this.refill();
    return this.opts.factory();
  }

  /** Drop transports older than maxAgeMs. Called on every take() and on a timer. */
  private expireStale(): void {
    const cutoff = Date.now() - this.opts.maxAgeMs;
    while (this.clients.length > 0 && this.clients[0].bornAt < cutoff) {
      const stale = this.clients.shift()!;
      try {
        stale.client.close();
      } catch {
        /* ignore */
      }
    }
  }

  /** Spawn handshakes until pool + in-flight reaches targetSize. */
  private refill(): void {
    if (this.closed) return;
    while (this.clients.length + this.connecting < this.opts.targetSize) {
      this.connecting++;
      this.opts
        .factory()
        .then((client) => {
          if (this.closed) {
            try {
              client.close();
            } catch {
              /* ignore */
            }
            return;
          }
          this.clients.push({ client, bornAt: Date.now() });
        })
        .catch((err: unknown) => {
          this.opts.onError?.(err instanceof Error ? err : new Error(String(err)));
        })
        .finally(() => {
          this.connecting--;
        });
    }
  }

  /** Close all pooled clients and stop refilling. */
  shutdown(): void {
    this.closed = true;
    for (const { client } of this.clients) {
      try {
        client.close();
      } catch {
        /* ignore */
      }
    }
    this.clients = [];
  }

  /** Pool status snapshot (mostly for logging). */
  status(): { warm: number; connecting: number } {
    return { warm: this.clients.length, connecting: this.connecting };
  }
}
