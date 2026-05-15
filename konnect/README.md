# @kawiri/konnect

TypeScript client for Kawiri's encrypted+attested inference tunnel. Works in browsers (modern WebKit/Chromium/Firefox) and from a CLI (Bun/Node). Ships a `konnect` binary that runs an OpenAI-compatible local proxy in front of the tunnel.

## Library

```ts
import { KawiriClient, KattValidator } from "@kawiri/konnect";

const client = new KawiriClient({
  url: "wss://api.kawiri.ai/v1/chat?model=qwen3-0.6b-q4-llamacpp-cpu_0.1.1",
  validator: new KattValidator({ allowMock: false, liveCollateral: true }),
  enablePQ: true,
});
await client.connect();

const stream = client.chatStream(
  [{ role: "user", content: "Hello" }],
  "qwen3-0.6b-q4-llamacpp-cpu_0.1.1",
);
for await (const token of stream) console.write(token);
```

For non-chat endpoints (embeddings, completions, /v1/models, /ping), use `client.requestRaw()` to get the upstream JSON verbatim:

```ts
const resp = await client.requestRaw("POST", "/v1/embeddings", {
  model: "qwen3-0.6b-…",
  input: ["hello world"],
});
console.log(resp.status, resp.body);
```

`client.request()` is still available but reshapes responses into a chat-shaped `ChatResult` — fine for chat endpoints, lossy for everything else.

## CLI — `konnect serve`

Runs an **OpenAI-compatible local proxy** in front of the tunnel. Any tool that speaks plain OpenAI HTTP (OpenWebUI, Continue, Cursor, llm-cli, LM Studio, …) points at `http://127.0.0.1:8090` and gets Kawiri E2E encryption + attestation underneath without speaking the WS protocol itself.

```
                                              konnect serve
local tool                                    ┌──────────────────────────┐
(OpenAI HTTP) ── localhost:8090 ────────────▶ │  HTTP server             │
                                              │  ↕ translate             │
                                              │  ClientPool              │
                                              │   • image A → WS         │
                                              │   • image B → WS         │
                                              │   • image C → WS         │
                                              └──────────┬───────────────┘
                                                         │
                                  wss://api.kawiri.ai/v1/chat?model=<image>
                                  (Authorization: Bearer kw_…)
                                                         │
                                                         ▼
                                          teehost ──▶ kawa ──▶ engine
```

### Quick start

```
bun install -g @kawiri/konnect

# minimum: api_key + which kcvm image to route to
KAWIRI_API_KEY=kw_xxx konnect serve --models qwen3-0.6b-q4-llamacpp-cpu_0.1.1
```

…then point your tool at `http://127.0.0.1:8090` and the OpenAI API base path `/v1`.

### Multi-model

One `konnect serve` process can hold N WS connections, one per kcvm image, sharing the same bearer:

```
konnect serve --models qwen3-0.6b-…,qwen3-1.7b-…,qwen3-4b-…
```

The first image in the list is the default-when-omitted. Each image gets its own attested handshake on first use, idle-evicts after a configurable window, and re-opens automatically on next request. A bad image doesn't affect the others.

### Config file

For ops-managed deployments, put everything in a TOML file and pass `--config`:

```
konnect serve --config ~/.kawiri/konnect.toml
```

See [`cli/example-config.toml`](cli/example-config.toml) for the full surface.

### API key resolution order

CLI flag > env var > config file. Pick one:

| Source | How |
|---|---|
| Flag | `--api-key kw_xxx` (shows in `ps` — fine for ad-hoc tests) |
| Env  | `KAWIRI_API_KEY=kw_xxx` (doesn't leak to `ps`) |
| File | `--api-key-file /path/to/key` or `api_key_file` in config (mode 0600 expected) |

### Routes the proxy exposes

| Route | Behavior |
|---|---|
| `GET /healthz` | Liveness, doesn't require tunnel |
| `GET /readyz` | 200 + JSON stats only when at least one tunnel is attested + connected |
| `GET /v1/models` | Synthesized: the configured images + every alias |
| `POST /v1/chat/completions` | Streaming SSE if `stream: true`, single JSON otherwise |
| `*` under `/v1/*` | Generic passthrough — body and status replayed verbatim from the engine. Embeddings, completions, audio, images, anything the kcvm engine serves works without per-route code |

### Model aliases

If your tool hardcodes a model name like `gpt-4o-mini`, set an alias:

```toml
models = ["qwen3-0.6b-q4-llamacpp-cpu_0.1.1"]

[aliases]
"gpt-4o-mini" = "qwen3-0.6b-q4-llamacpp-cpu_0.1.1"
```

Every alias target must appear in `models` — the proxy validates this on startup.

### Security notes

- The proxy is bound to `127.0.0.1` by default. Don't bind it to a public interface without also setting `[security].local_token`. The token is compared in constant time.
- `allow_mock_attestation = true` accepts kawa instances running with the `mock` cargo feature. **Dev only.** Production deployments must leave it off so the real TEE quote is verified.
- The api_key lives in the `konnect serve` process. Each kcvm image gets its own WS upgrade with the same bearer; the router enforces per-key rate limits and quota.
- On startup, the proxy eager-connects the default model so attestation failures and bad api_keys fail-fast (exit 1) rather than at first user-visible request.

### Other subcommands

```
konnect chat --message "hello"           # one-shot streaming chat to stdout
echo "summarize this" | konnect chat     # reads stdin if --message is omitted

konnect ping                             # connect + attest + /ping; exit 0/1
                                         # useful for CI / monitoring probes
```

Both reuse the same config + env + flag layering as `serve`.

### Why a local proxy at all

Kawiri's tunnel is a custom Noise XX + X-Wing PQ protocol carried over a WebSocket. No standard OpenAI client speaks it. The proxy runs on the user's machine — **inside the trust boundary that already terminates the encrypted+attested tunnel** — so it can decrypt and translate without weakening the E2E guarantee. Exposing OpenAI-shaped HTTPS on the router edge would defeat that: the router would have to decrypt, and the CVM would stop being the trust anchor.
