# @kawiri/konnect

TypeScript client for Kawiri's encrypted+attested inference tunnel. Works in browsers (Bun, modern WebKit/Chromium/Firefox) and from a CLI (Bun/Node).

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

## CLI

`konnect serve` runs an **OpenAI-compatible local proxy** in front of the tunnel — any tool that speaks plain OpenAI HTTP (OpenWebUI, Continue, Cursor, llm-cli, LM Studio, …) points at `http://127.0.0.1:8090` and gets Kawiri E2E encryption + attestation underneath without speaking the WS protocol itself.

```
                                       konnect serve
local tool                             ┌────────────────┐
(OpenAI HTTP) ─── localhost:8090 ────▶ │  HTTP server   │
                                       │  ↕ translate   │
                                       │  Noise / X-Wing│
                                       └────────┬───────┘
                                                │
                                                ▼
                                  wss://api.kawiri.ai/v1/chat
                                                │
                                                ▼
                                       teehost ──▶ kawa ──▶ llama.cpp / vLLM
```

### Quick start

```
bun install -g @kawiri/konnect

# minimum: api_key + which kcvm image to route to
KAWIRI_API_KEY=kw_xxx konnect serve --model qwen3-0.6b-q4-llamacpp-cpu_0.1.1
```

…then point your tool at `http://127.0.0.1:8090` and the OpenAI API base path `/v1`.

### Config file

For ops-managed deployments, put everything in a TOML file and pass `--config`:

```
konnect serve --config ~/.kawiri/konnect.toml
```

See [`cli/example-config.toml`](cli/example-config.toml) for the full surface.

### API key resolution order

Flag > env var > config file. Pick one:

| Source | How |
|---|---|
| Flag | `--api-key kw_xxx` (shows in `ps` — fine for ad-hoc tests) |
| Env  | `KAWIRI_API_KEY=kw_xxx` (doesn't leak to `ps`) |
| File | `--api-key-file /path/to/key` or `api_key_file` in config (mode 0600 expected) |

### Routes the proxy exposes

| Route | Behavior |
|---|---|
| `GET /healthz` | Liveness, doesn't require tunnel |
| `GET /readyz` | 200 only when the tunnel is attested + connected |
| `GET /v1/models` | Synthesized: the configured model + every alias |
| `POST /v1/chat/completions` | Streaming SSE if `stream: true`, single JSON otherwise |
| `POST /v1/completions` | Generic passthrough |
| `POST /v1/embeddings` | Generic passthrough |
| `*/v1/*` | Generic passthrough — anything the engine inside the CVM supports works without per-route code |

### Model aliases

If your tool hardcodes a model name like `gpt-4o-mini`, set an alias:

```toml
[aliases]
"gpt-4o-mini" = "qwen3-0.6b-q4-llamacpp-cpu_0.1.1"
```

`/v1/models` then advertises both names; requests for either route to the configured image.

### Security notes

- The proxy is bound to `127.0.0.1` by default. Don't bind it to a public interface without also setting `[security].local_token`.
- `allow_mock_attestation = true` accepts kawa instances running with the `mock` cargo feature. **Dev only.** Production deployments must leave it off so the real TEE quote is verified.
- The api_key lives in `konnect serve`'s process memory. The proxy holds one long-lived WS connection per process; on first request it eager-connects + verifies attestation, so a bad key or attestation mismatch fails at startup, not at first user-visible request.

### Why a local proxy at all

Kawiri's tunnel is a custom Noise XX + X-Wing PQ protocol carried over a WebSocket. No standard OpenAI client speaks it. The proxy runs on the user's machine — **inside the trust boundary that already terminates the encrypted+attested tunnel** — so it can decrypt and translate without weakening the E2E guarantee. Exposing OpenAI-shaped HTTPS on the router edge would defeat that: the router would have to decrypt, and the CVM would stop being the trust anchor.
