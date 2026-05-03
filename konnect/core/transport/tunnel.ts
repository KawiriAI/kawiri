/**
 * Tunnel — opaque byte channel over a kawa transport after a successful
 * `tunnel.open` handshake. The KawiriClient that produced this Tunnel
 * is consumed: chat() and request() will throw, because every WS frame
 * the client receives from this point on is interpreted as raw tunnel
 * bytes (no JSON wrapper).
 *
 * Lifetime: the tunnel is one-shot — closing it closes the underlying
 * WebSocket. konnect-proxy's warm-transport pool deals with that by
 * spinning up a fresh client per local TCP connection.
 *
 * Ordering: send() awaits the encrypt+ws.send round-trip so callers
 * can't get out-of-order frames on the wire. onData fires synchronously
 * from the WS message handler, so consumers should be cheap (e.g.
 * forward bytes to a TCP socket) or post-process via their own queue.
 */
export interface Tunnel {
  /** Push bytes toward the remote loopback port. Resolves when the
   *  encrypted frame has been handed to the WebSocket. Throws if the
   *  tunnel is closed or the bytes exceed a single Noise frame. */
  send(bytes: Uint8Array): Promise<void>;

  /** Bytes received from the remote loopback port. Set this before any
   *  data is expected — frames that arrive before a handler is attached
   *  are dropped (same shape as Bun.listen socket.data). */
  onData: ((bytes: Uint8Array) => void) | null;

  /** Fires once when the tunnel transitions to closed (server EOF, WS
   *  close, or local close()). Idempotent — never fires twice. */
  onClose: (() => void) | null;

  /** True after onClose has fired or close() was called. */
  readonly closed: boolean;

  /** Close the tunnel and the underlying transport. Idempotent. */
  close(): void;
}

/** Thrown by KawiriClient.openTunnel when the server replies with
 *  `tunnel.error`. Carries the server-supplied reason for surface in
 *  konnect-proxy's CLI output. */
export class TunnelOpenError extends Error {
  constructor(public readonly reason: string) {
    super(`tunnel.open denied: ${reason}`);
    this.name = "TunnelOpenError";
  }
}
