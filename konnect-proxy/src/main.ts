#!/usr/bin/env bun
import { readFileSync } from "node:fs";
import {
  type AttestationValidator,
  KattValidator,
  KawiriClient,
  StubValidator,
  type Tunnel,
  TunnelOpenError,
} from "@kawiri/konnect";
import { WarmPool } from "./pool.ts";

interface CliOpts {
  to: string;
  tunnels: { local: number; remote: number }[];
  manifest: string | null;
  acceptMock: boolean;
  poolSize: number;
  poolMaxAgeSec: number;
  enablePQ: boolean;
  verbose: boolean;
}

const USAGE = `\
konnect-proxy — attestation-gated TCP tunnel into a Kawiri CVM

Usage:
  konnect-proxy --to <ws-url> --tunnel <local:remote> [options]

Required:
  --to <url>            Kawa endpoint, e.g. wss://my-host:13212
  --tunnel <L:R>        Forward local TCP :L → CVM loopback :R (repeatable)

Validation (one required):
  --manifest <path>     JSON manifest with expected SNP/TDX measurements
  --accept-mock         DEV ONLY — accept mock attestation, no TEE backing

Pool:
  --pool-size <n>       Warm transport pool depth (default 2)
  --pool-max-age <sec>  Refresh transports older than this (default 300)

Other:
  --no-pq               Disable post-quantum upgrade (kawa must agree)
  --verbose             Log handshake timing + pool status
  --help                Show this message

Example:
  konnect-proxy --to wss://my-host:13212 --tunnel 2222:22 \\
    --manifest ./build/manifest.json
  ssh -i kawiri-test -o UserKnownHostsFile=/dev/null \\
    -o StrictHostKeyChecking=no -p 2222 root@127.0.0.1
`;

function parseArgs(argv: string[]): CliOpts {
  const opts: CliOpts = {
    to: "",
    tunnels: [],
    manifest: null,
    acceptMock: false,
    poolSize: 2,
    poolMaxAgeSec: 300,
    enablePQ: true,
    verbose: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case "--help":
      case "-h":
        process.stdout.write(USAGE);
        process.exit(0);
        break;
      case "--to":
        opts.to = argv[++i] ?? "";
        break;
      case "--tunnel": {
        const spec = argv[++i] ?? "";
        const [l, r] = spec.split(":");
        const local = Number(l);
        const remote = Number(r);
        if (!Number.isFinite(local) || !Number.isFinite(remote)) {
          die(`bad --tunnel ${spec} (expected LOCAL:REMOTE)`);
        }
        opts.tunnels.push({ local, remote });
        break;
      }
      case "--manifest":
        opts.manifest = argv[++i] ?? null;
        break;
      case "--accept-mock":
        opts.acceptMock = true;
        break;
      case "--pool-size":
        opts.poolSize = Math.max(1, Number(argv[++i] ?? "2"));
        break;
      case "--pool-max-age":
        opts.poolMaxAgeSec = Math.max(60, Number(argv[++i] ?? "300"));
        break;
      case "--no-pq":
        opts.enablePQ = false;
        break;
      case "--verbose":
        opts.verbose = true;
        break;
      default:
        die(`unknown arg: ${a}\n\n${USAGE}`);
    }
  }
  if (!opts.to) die("missing --to");
  if (opts.tunnels.length === 0) die("need at least one --tunnel L:R");
  if (!opts.manifest && !opts.acceptMock) {
    die("must pass --manifest <path> or --accept-mock (DEV ONLY)");
  }
  return opts;
}

function die(msg: string): never {
  process.stderr.write(`konnect-proxy: ${msg}\n`);
  process.exit(2);
}

function loadValidator(opts: CliOpts): AttestationValidator {
  if (opts.acceptMock && !opts.manifest) {
    // Pure-mock dev mode — accept anything, log loudly.
    console.warn(
      "[konnect-proxy] ⚠ --accept-mock with no manifest: accepting ALL attestations. " +
        "Use only for local dev against a mock kawa.",
    );
    return new StubValidator();
  }
  if (opts.manifest) {
    const raw = readFileSync(opts.manifest, "utf8");
    const manifest = JSON.parse(raw) as Record<string, unknown>;
    // Manifest format from cvmbuild — see kcvm/images/*/manifest.expected.json.
    // The relevant blocks are manifest.snp and manifest.tdx; lift them into
    // the ExpectedMeasurements shape KattValidator wants.
    const expected = {
      snp: extractSnp(manifest),
      tdx: extractTdx(manifest),
    };
    return new KattValidator({
      expectedMeasurements: expected,
      allowMock: opts.acceptMock,
      liveCollateral: true,
    });
  }
  return new StubValidator();
}

// cvmbuild's manifest.expected.json carries `snp.launch_digest_<cpu>` keys
// (Milan, Genoa, etc.) inside a `manifest.snp` block. KattValidator expects
// `{ "Milan": "<hex>", ... }`. Translate.
function extractSnp(m: Record<string, unknown>): Record<string, string> | undefined {
  const snp = (m.manifest as Record<string, unknown> | undefined)?.snp as
    | Record<string, unknown>
    | undefined;
  if (!snp) return undefined;
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(snp)) {
    const m = k.match(/^launch_digest_(.+)$/);
    if (m && typeof v === "string") {
      // Capitalize first letter to match KattValidator convention (Milan, Genoa, …).
      const cpu = m[1][0].toUpperCase() + m[1].slice(1).toLowerCase();
      out[cpu] = v;
    }
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

function extractTdx(
  m: Record<string, unknown>,
): { mrtd?: string; rtmr0?: string; rtmr1?: string; rtmr2?: string } | undefined {
  const tdx = (m.manifest as Record<string, unknown> | undefined)?.tdx as
    | Record<string, unknown>
    | undefined;
  if (!tdx) return undefined;
  return {
    mrtd: tdx.mrtd as string | undefined,
    rtmr0: tdx.rtmr0 as string | undefined,
    rtmr1: tdx.rtmr1 as string | undefined,
    rtmr2: tdx.rtmr2 as string | undefined,
  };
}

async function buildClient(opts: CliOpts, validator: AttestationValidator): Promise<KawiriClient> {
  const c = new KawiriClient({
    url: opts.to,
    validator,
    enablePQ: opts.enablePQ,
    debug: opts.verbose,
  });
  await c.connect();
  return c;
}

function startListener(
  localPort: number,
  remotePort: number,
  pool: WarmPool,
  verbose: boolean,
): void {
  Bun.listen<TunnelSocketData>({
    hostname: "127.0.0.1",
    port: localPort,
    socket: {
      open(socket) {
        if (verbose) {
          const s = pool.status();
          console.log(
            `[konnect-proxy] :${localPort} → :${remotePort} (warm=${s.warm}, connecting=${s.connecting})`,
          );
        } else {
          console.log(`[konnect-proxy] :${localPort} → :${remotePort}`);
        }
        socket.data = { tunnel: null, pending: [], closed: false };

        // Acquire a transport + open a tunnel asynchronously. Bytes from
        // the local side that arrive before the tunnel is ready are buffered
        // in socket.data.pending and flushed on tunnel.opened.
        (async () => {
          const client = await pool.take().catch((e) => {
            console.error(
              `[konnect-proxy] pool.take failed: ${e instanceof Error ? e.message : e}`,
            );
            socket.end();
            return null;
          });
          if (!client) return;

          let tunnel: Tunnel;
          try {
            tunnel = await client.openTunnel(remotePort);
          } catch (e) {
            if (e instanceof TunnelOpenError) {
              console.error(`[konnect-proxy] tunnel.open denied: ${e.reason}`);
            } else {
              console.error(
                `[konnect-proxy] tunnel.open failed: ${e instanceof Error ? e.message : e}`,
              );
            }
            socket.end();
            client.close();
            return;
          }

          if (socket.data.closed) {
            // Local side already gave up — don't bother wiring.
            tunnel.close();
            return;
          }

          tunnel.onData = (bytes) => {
            socket.write(bytes);
          };
          tunnel.onClose = () => {
            socket.end();
          };

          // Flush any bytes that arrived while we were handshaking.
          for (const chunk of socket.data.pending) {
            tunnel.send(chunk).catch((e) => {
              console.error(
                `[konnect-proxy] tunnel.send (flush) failed: ${e instanceof Error ? e.message : e}`,
              );
              socket.end();
            });
          }
          socket.data.pending = [];
          socket.data.tunnel = tunnel;
        })();
      },
      data(socket, chunk) {
        const t = socket.data.tunnel;
        const bytes = new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength);
        if (!t) {
          socket.data.pending.push(bytes);
          return;
        }
        t.send(bytes).catch((e) => {
          console.error(`[konnect-proxy] tunnel.send failed: ${e instanceof Error ? e.message : e}`);
          socket.end();
        });
      },
      close(socket) {
        socket.data.closed = true;
        const t = socket.data.tunnel;
        if (t && !t.closed) t.close();
      },
      error(socket, err) {
        console.error(`[konnect-proxy] socket error: ${err.message}`);
        socket.data.closed = true;
        const t = socket.data.tunnel;
        if (t && !t.closed) t.close();
      },
    },
  });
  console.log(`[konnect-proxy] listening on 127.0.0.1:${localPort} → CVM 127.0.0.1:${remotePort}`);
}

interface TunnelSocketData {
  tunnel: Tunnel | null;
  pending: Uint8Array[];
  closed: boolean;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const validator = loadValidator(opts);

  const pool = new WarmPool({
    targetSize: opts.poolSize,
    maxAgeMs: opts.poolMaxAgeSec * 1000,
    factory: () => buildClient(opts, validator),
    onError: (err) => console.error(`[konnect-proxy] pool refill error: ${err.message}`),
  });

  for (const t of opts.tunnels) {
    startListener(t.local, t.remote, pool, opts.verbose);
  }

  // Graceful shutdown
  const shutdown = (sig: string) => {
    console.log(`[konnect-proxy] ${sig} — shutting down`);
    pool.shutdown();
    process.exit(0);
  };
  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));

  console.log(
    `[konnect-proxy] kawa=${opts.to} pool=${opts.poolSize} max-age=${opts.poolMaxAgeSec}s pq=${opts.enablePQ}`,
  );
}

main().catch((e) => {
  console.error(`[konnect-proxy] fatal: ${e instanceof Error ? e.message : e}`);
  process.exit(1);
});
