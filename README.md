# kawiri

Secure, attested AI inference on confidential VMs.

## Components

| Directory | Description |
|---|---|
| `konnect/` | TypeScript client — Noise XX encrypted transport with hardware attestation verification |
| `kawa/` | Rust server — Noise handshake responder, TEE attestation, upstream proxy |
| `kcvm/` | Confidential VM image definitions — Dockerfiles and manifests for inference engines |
| `firmware/` | OVMF firmware patches for CVM hardening |

## Building

### kawa (server)

```bash
cd kawa
cargo build --release
# Binary: target/release/kawa
```

### konnect (client library)

```bash
cd konnect
bun install
bun test core/test/ katt/test/
```

### CVM images

Requires [cvmbuild](https://github.com/KawiriAI/cvmbuild/releases):

```bash
# Build the kawa binary first
cd kawa && cargo build --release && cd ..

# Build a CVM image
cvmbuild build kcvm/images/qwen3-0.6b-q4-llamacpp-cpu
```

See `kcvm/images/` for available image definitions.

## License

Business Source License 1.1 — see [LICENSE](LICENSE).
