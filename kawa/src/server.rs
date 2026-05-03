use std::net::SocketAddr;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_tungstenite::tungstenite::Message;
use hyper_tungstenite::HyperWebsocket;
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use tracing::{debug, info, warn};

/// Max concurrent WebSocket handshakes (Noise + attestation).
/// Prevents resource exhaustion from connection floods.
const MAX_CONCURRENT_HANDSHAKES: usize = 50;

// ── TDX v4 quote layout (Intel TDX DCAP Quote Generation §A.3.1) ────────────
//   48-byte header, then 584-byte TD Report body.
//   Body fields (sequential): teeTcbSvn(16) mrseam(48) mrsignerseam(48)
//   seamattr(8) tdattr(8) xfam(8) MRTD(48) mrconfigid(48) mrowner(48)
//   mrownerconfig(48) RTMR0(48) RTMR1(48) RTMR2(48) RTMR3(48) reportdata(64)
const TDX_HEADER: usize = 48;
const TDX_MRTD: usize = TDX_HEADER + 136; // 16+48+48+8+8+8 = 136 bytes before MRTD
const TDX_RTMR0: usize = TDX_MRTD + 192; // MRTD(48)+mrconfigid(48)+mrowner(48)+mrownerconfig(48)
const TDX_RTMR1: usize = TDX_RTMR0 + 48;
const TDX_RTMR2: usize = TDX_RTMR1 + 48;
const TDX_RTMR3: usize = TDX_RTMR2 + 48;
const TDX_MIN_LEN: usize = TDX_RTMR3 + 48;

// ── SEV-SNP attestation report layout (AMD SEV-SNP ABI §7.3, Table 21) ──────
const SNP_REPORT_DATA: usize = 0x50; // 64 bytes
const SNP_MEASUREMENT: usize = 0x90; // 48 bytes (launch digest)
const SNP_HOST_DATA: usize = 0xc0; // 32 bytes
const SNP_MIN_LEN: usize = 0xe0; // through end of hostData

use crate::config::Config;
use crate::protocol::framer::{self, FrameAssembler};
use crate::protocol::noise::{NoiseResponder, StaticKeypair};
use crate::protocol::transport::EncryptedTransport;
use crate::protocol::types::{
    FirstMessagePeek, KawiriRequest, KawiriResponse, KawiriStreamChunk, TunnelError, TunnelOpen,
    TunnelOpened,
};
use crate::proxy::{self, ProxyEvent};
use crate::tee::{self, TeeMode};
use crate::tunnel;

pub async fn start_server(config: Config, tee_mode: TeeMode) -> anyhow::Result<()> {
    let static_keypair = Arc::new(StaticKeypair::generate()?);

    // ── Boot banner ──────────────────────────────────────────────
    log_system_info(&config, tee_mode);

    let config = Arc::new(config);
    let http_client = Arc::new(reqwest::Client::new());
    let handshake_semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_HANDSHAKES));

    // Ping teehost on startup to check vsock connectivity
    match tee::vsock_teehost::ping_teehost().await {
        Ok(status) => info!("teehost reachable: {status}"),
        Err(e) => warn!("teehost not reachable: {e} (vsock cert fallback will be unavailable)"),
    }

    // Pre-generate and cache TEE attestation so the first client doesn't pay
    // the ~1s firmware roundtrip. Mock mode skips this — its payload is a
    // ~zero-cost placeholder anyway and we'd rather see the per-handshake
    // WARN every time it's served, not silently cached.
    if tee_mode == TeeMode::Real {
        let t0 = std::time::Instant::now();
        match tee::generate_attestation(static_keypair.public_key(), tee_mode).await {
            Ok(ref payload) => {
                let elapsed = t0.elapsed();
                info!("attestation cached in {:.0?}", elapsed);
                log_attestation(payload);
            }
            Err(e) => warn!("attestation pre-cache failed: {e} (will retry on first connection)"),
        }
    }

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    let listener = TcpListener::bind(addr).await?;
    info!(addr = %addr, "listening");

    loop {
        let (stream, _peer) = listener.accept().await?;
        let config = Arc::clone(&config);
        let keypair = Arc::clone(&static_keypair);
        let client = Arc::clone(&http_client);
        let semaphore = Arc::clone(&handshake_semaphore);

        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let config_c = Arc::clone(&config);
            let keypair_c = Arc::clone(&keypair);
            let client_c = Arc::clone(&client);
            let sem_c = Arc::clone(&semaphore);

            let conn = http1::Builder::new().serve_connection(
                io,
                service_fn(move |req| {
                    let config = Arc::clone(&config_c);
                    let keypair = Arc::clone(&keypair_c);
                    let client = Arc::clone(&client_c);
                    let sem = Arc::clone(&sem_c);
                    async move { handle_request(req, config, keypair, client, sem, tee_mode).await }
                }),
            );

            if let Err(e) = conn.with_upgrades().await {
                // teehost's per-poll probes against /health and /mode end with
                // a clean client-side close that hyper still surfaces as
                // "connection closed before message completed". Demote that
                // benign case so it doesn't drown the operator's log; real
                // truncated requests / half-WebSocket-handshakes have other
                // strings and stay loud.
                let msg = e.to_string();
                if msg.contains("connection closed before message completed") {
                    debug!(error = %e, "connection error (benign close)");
                } else {
                    warn!(error = %e, "connection error");
                }
            }
        });
    }
}

async fn handle_request(
    mut req: Request<Incoming>,
    config: Arc<Config>,
    keypair: Arc<StaticKeypair>,
    http_client: Arc<reqwest::Client>,
    handshake_semaphore: Arc<Semaphore>,
    tee_mode: TeeMode,
) -> Result<Response<Full<Bytes>>, anyhow::Error> {
    // Health endpoint
    if req.uri().path() == "/health" {
        return Ok(Response::builder()
            .header("connection", "close")
            .body(Full::new("ok".into()))?);
    }

    // Mode endpoint — teehost probes this to surface "real" vs "mock" in the
    // VM list. Self-reported by kawa; fine for operator UI (konnect remains
    // the trust anchor for clients via the signed attestation envelope).
    if req.uri().path() == "/mode" {
        let body = match tee_mode {
            TeeMode::Real => "{\"mode\":\"real\"}",
            TeeMode::Mock => "{\"mode\":\"mock\"}",
        };
        return Ok(Response::builder()
            .header("content-type", "application/json")
            .header("connection", "close")
            .body(Full::new(body.into()))?);
    }

    // Check for WebSocket upgrade
    if !hyper_tungstenite::is_upgrade_request(&req) {
        return Ok(Response::builder()
            .status(426)
            .body(Full::new("Expected WebSocket".into()))?);
    }

    let (response, websocket) = hyper_tungstenite::upgrade(&mut req, None)?;

    tokio::spawn(async move {
        // Acquire semaphore permit before handshake — limits concurrent Noise+attestation
        let _permit = match handshake_semaphore.acquire().await {
            Ok(permit) => permit,
            Err(_) => {
                warn!("handshake semaphore closed");
                return;
            }
        };

        if let Err(e) = handle_websocket(websocket, config, keypair, http_client, tee_mode).await {
            warn!(error = %e, "websocket handler error");
        }
    });

    Ok(response)
}

async fn handle_websocket(
    websocket: HyperWebsocket,
    config: Arc<Config>,
    keypair: Arc<StaticKeypair>,
    http_client: Arc<reqwest::Client>,
    tee_mode: TeeMode,
) -> anyhow::Result<()> {
    let ws = websocket.await?;
    let (mut ws_sink, mut ws_stream) = ws.split();

    // Helper: receive next binary WebSocket message
    macro_rules! recv_binary {
        ($stream:expr) => {
            loop {
                match $stream.next().await {
                    Some(Ok(Message::Binary(data))) => break Ok(data.to_vec()),
                    Some(Ok(Message::Close(_))) | None => {
                        break Err(anyhow::anyhow!("connection closed"))
                    }
                    Some(Ok(_)) => continue, // skip ping/pong/text
                    Some(Err(e)) => break Err(e.into()),
                }
            }
        };
    }

    // --- Phase 1: Noise_XX Handshake ---
    let mut responder = NoiseResponder::new(&keypair.keypair)?;

    // msg 0: read client ephemeral
    let msg0: Vec<u8> = recv_binary!(ws_stream)?;
    responder.read_msg0(&msg0)?;

    // Generate attestation. In mock mode this returns instantly with a
    // placeholder payload; the WARN inside generate_attestation already
    // fires per-handshake.
    let attestation = tee::generate_attestation(keypair.public_key(), tee_mode).await?;
    let attestation_json = serde_json::to_vec(&attestation)?;

    // msg 1: send ephemeral + static + attestation
    let msg1 = responder.write_msg1(&attestation_json)?;
    ws_sink.send(Message::binary(msg1)).await?;

    // msg 2: read client static
    let msg2: Vec<u8> = recv_binary!(ws_stream)?;
    responder.read_msg2(&msg2)?;

    let mut transport: Box<dyn EncryptedTransport> = Box::new(responder.into_transport()?);

    // --- Phase 2: Optional XWing PQ upgrade ---
    if config.enable_pq {
        info!("starting XWing post-quantum upgrade");

        let new_transport =
            xwing_upgrade_inline(transport.as_mut(), &mut ws_sink, &mut ws_stream).await?;
        transport = Box::new(new_transport);
        info!("XWing upgrade complete");
    }

    // --- Phase 3: Transport message loop ---
    let mut assembler = FrameAssembler::new();
    let mut first_message = true;

    loop {
        let raw: Vec<u8> = match recv_binary!(ws_stream) {
            Ok(data) => data,
            Err(_) => break,
        };

        // Loud per-message warning in mock mode — the user-chosen audit trail.
        // Volume is intentional: every recv on a non-attested connection is one
        // log line so an operator skimming logs can't miss it. (In tunnel mode
        // this fires only for the tunnel.open control message; the tunnel
        // relay loop is silent to avoid drowning the log on busy SSH sessions.)
        if tee_mode == TeeMode::Mock {
            warn!("kawa: received message on MOCK connection (no TEE attestation backing this transport)");
        }

        // Decrypt
        let plain_frame = transport.decrypt(&raw)?;

        // Decode frame
        let decoded = framer::decode(&plain_frame)?;

        // Assemble (handles chunked frames)
        let payload = match assembler.process(decoded)? {
            Some(p) => p,
            None => continue,
        };

        // First complete message decides the channel mode: a JSON object
        // with `kind:"tunnel.open"` switches us into tunnel relay mode for
        // the rest of the connection. Anything else (no `kind` field) flows
        // through to the existing RPC handler unchanged.
        if first_message {
            first_message = false;
            if let Ok(peek) = serde_json::from_slice::<FirstMessagePeek>(&payload) {
                if peek.kind.as_deref() == Some("tunnel.open") {
                    handle_tunnel_open(
                        &payload,
                        &config,
                        transport.as_mut(),
                        &mut ws_sink,
                        &mut ws_stream,
                        tee_mode,
                    )
                    .await?;
                    return Ok(());
                }
            }
        }

        // Parse request
        let req: KawiriRequest = serde_json::from_slice(&payload)?;
        let is_stream = req
            .body
            .as_ref()
            .and_then(|b| b.get("stream"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // Handle request
        if req.path == "/ping" {
            let resp = KawiriResponse {
                id: req.id,
                status: 200,
                body: Some(serde_json::Value::String("pong".into())),
            };
            send_encrypted_response(transport.as_mut(), &mut ws_sink, &resp).await?;
            continue;
        }

        if !req.path.starts_with("/v1/") {
            let chunk = KawiriStreamChunk {
                id: req.id,
                event: "error".into(),
                data: Some(serde_json::Value::String(format!(
                    "Invalid path: {}",
                    req.path
                ))),
            };
            send_encrypted_chunk(transport.as_mut(), &mut ws_sink, &chunk).await?;
            continue;
        }

        // Standalone mode
        if config.is_standalone() {
            handle_standalone(&req, is_stream, transport.as_mut(), &mut ws_sink).await?;
            continue;
        }

        // Proxy to upstream
        let (tx, mut rx) = mpsc::channel::<ProxyEvent>(32);
        let client = Arc::clone(&http_client);
        let upstream = config.upstream.clone();
        let method = req.method.clone();
        let path = req.path.clone();
        let body = req.body.clone();

        tokio::spawn(async move {
            proxy::proxy_to_upstream(
                &upstream,
                &client,
                &method,
                &path,
                body.as_ref(),
                is_stream,
                tx,
            )
            .await;
        });

        let req_id = req.id;
        while let Some(event) = rx.recv().await {
            match event {
                ProxyEvent::Chunk(data) => {
                    if is_stream {
                        let chunk = KawiriStreamChunk {
                            id: req_id,
                            event: "data".into(),
                            data: Some(serde_json::Value::String(data)),
                        };
                        send_encrypted_chunk(transport.as_mut(), &mut ws_sink, &chunk).await?;
                    } else {
                        let body = serde_json::from_str::<serde_json::Value>(&data)
                            .unwrap_or(serde_json::Value::String(data));
                        let resp = KawiriResponse {
                            id: req_id,
                            status: 200,
                            body: Some(body),
                        };
                        send_encrypted_response(transport.as_mut(), &mut ws_sink, &resp).await?;
                    }
                }
                ProxyEvent::Done => {
                    if is_stream {
                        let chunk = KawiriStreamChunk {
                            id: req_id,
                            event: "done".into(),
                            data: None,
                        };
                        send_encrypted_chunk(transport.as_mut(), &mut ws_sink, &chunk).await?;
                    }
                }
                ProxyEvent::Error(msg) => {
                    let chunk = KawiriStreamChunk {
                        id: req_id,
                        event: "error".into(),
                        data: Some(serde_json::Value::String(msg)),
                    };
                    send_encrypted_chunk(transport.as_mut(), &mut ws_sink, &chunk).await?;
                }
            }
        }
    }

    info!("connection closed");
    Ok(())
}

/// Perform XWing upgrade inline (avoids closure borrow issues).
async fn xwing_upgrade_inline<S, R>(
    transport: &mut dyn EncryptedTransport,
    ws_sink: &mut S,
    ws_stream: &mut R,
) -> anyhow::Result<crate::protocol::transport::AesGcmTransport>
where
    S: futures_util::Sink<Message, Error = hyper_tungstenite::tungstenite::Error> + Unpin,
    R: futures_util::Stream<Item = Result<Message, hyper_tungstenite::tungstenite::Error>> + Unpin,
{
    use crate::protocol::types::{XWingUpgradeMsg1, XWingUpgradeMsg2};
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;

    // Generate keypair
    let (dk_bytes, ek_bytes) = crate::protocol::xwing::generate_keypair();

    // Send public key
    let msg1 = XWingUpgradeMsg1 {
        msg_type: "pq-upgrade".into(),
        public_key: BASE64.encode(&ek_bytes),
    };
    let msg1_json = serde_json::to_vec(&msg1)?;
    let encrypted = transport.encrypt(&msg1_json)?;
    ws_sink.send(Message::binary(encrypted)).await?;

    // Receive ciphertext
    let raw = loop {
        match ws_stream.next().await {
            Some(Ok(Message::Binary(data))) => break data.to_vec(),
            Some(Ok(Message::Close(_))) | None => {
                return Err(anyhow::anyhow!("connection closed during xwing"));
            }
            Some(Ok(_)) => continue,
            Some(Err(e)) => return Err(e.into()),
        }
    };
    let decrypted = transport.decrypt(&raw)?;
    let msg2: XWingUpgradeMsg2 = serde_json::from_slice(&decrypted)?;

    if msg2.msg_type != "pq-upgrade-reply" {
        return Err(anyhow::anyhow!(
            "unexpected xwing message: {}",
            msg2.msg_type
        ));
    }

    // Decapsulate
    let ct_bytes = BASE64.decode(&msg2.cipher_text)?;
    let shared_secret = crate::protocol::xwing::decapsulate(&dk_bytes, &ct_bytes)
        .map_err(|e| anyhow::anyhow!("xwing decapsulate: {e}"))?;

    // Derive keys
    let (send_key, recv_key) = crate::protocol::xwing::derive_keys(&shared_secret, false)
        .map_err(|e| anyhow::anyhow!("xwing hkdf: {e}"))?;

    Ok(crate::protocol::transport::AesGcmTransport::new(
        &send_key, &recv_key,
    ))
}

/// Encrypt and send a serializable response over WebSocket.
async fn send_encrypted_response<S>(
    transport: &mut dyn EncryptedTransport,
    ws_sink: &mut S,
    resp: &KawiriResponse,
) -> anyhow::Result<()>
where
    S: futures_util::Sink<Message, Error = hyper_tungstenite::tungstenite::Error> + Unpin,
{
    let bytes = serde_json::to_vec(resp)?;
    send_encrypted_bytes(transport, ws_sink, &bytes).await
}

/// Encrypt and send a serializable stream chunk over WebSocket.
async fn send_encrypted_chunk<S>(
    transport: &mut dyn EncryptedTransport,
    ws_sink: &mut S,
    chunk: &KawiriStreamChunk,
) -> anyhow::Result<()>
where
    S: futures_util::Sink<Message, Error = hyper_tungstenite::tungstenite::Error> + Unpin,
{
    let bytes = serde_json::to_vec(chunk)?;
    send_encrypted_bytes(transport, ws_sink, &bytes).await
}

/// Encrypt, frame, and send raw bytes over WebSocket.
async fn send_encrypted_bytes<S>(
    transport: &mut dyn EncryptedTransport,
    ws_sink: &mut S,
    data: &[u8],
) -> anyhow::Result<()>
where
    S: futures_util::Sink<Message, Error = hyper_tungstenite::tungstenite::Error> + Unpin,
{
    let frames = framer::encode(data);
    for frame in frames {
        let encrypted = transport.encrypt(&frame)?;
        ws_sink.send(Message::binary(encrypted)).await?;
    }
    Ok(())
}

/// Handle a `tunnel.open` control message: validate against the allowlist,
/// dial the loopback port, send back `tunnel.opened` or `tunnel.error`, then
/// hand the transport over to the byte relay until either side closes.
async fn handle_tunnel_open<S, R>(
    payload: &[u8],
    config: &Config,
    transport: &mut dyn EncryptedTransport,
    ws_sink: &mut S,
    ws_stream: &mut R,
    tee_mode: TeeMode,
) -> anyhow::Result<()>
where
    S: futures_util::Sink<Message, Error = hyper_tungstenite::tungstenite::Error> + Unpin,
    R: futures_util::Stream<Item = Result<Message, hyper_tungstenite::tungstenite::Error>> + Unpin,
{
    let open: TunnelOpen =
        serde_json::from_slice(payload).map_err(|e| anyhow::anyhow!("tunnel.open parse: {e}"))?;

    if !config.tunnel_ports.contains(&open.port) {
        let msg = format!("port {} not in tunnel allowlist", open.port);
        warn!("tunnel.open rejected: {msg}");
        send_tunnel_error(transport, ws_sink, &msg).await?;
        return Ok(());
    }

    let socket = match TcpStream::connect(("127.0.0.1", open.port)).await {
        Ok(s) => s,
        Err(e) => {
            let msg = format!("connect 127.0.0.1:{} failed: {e}", open.port);
            warn!("tunnel.open: {msg}");
            send_tunnel_error(transport, ws_sink, &msg).await?;
            return Ok(());
        }
    };

    send_tunnel_opened(transport, ws_sink).await?;

    let attestation_label = match tee_mode {
        TeeMode::Real => "real",
        TeeMode::Mock => "MOCK",
    };
    info!(
        "tunnel: opened to 127.0.0.1:{} (attestation={})",
        open.port, attestation_label
    );

    tunnel::relay(transport, ws_sink, ws_stream, socket).await
}

async fn send_tunnel_opened<S>(
    transport: &mut dyn EncryptedTransport,
    ws_sink: &mut S,
) -> anyhow::Result<()>
where
    S: futures_util::Sink<Message, Error = hyper_tungstenite::tungstenite::Error> + Unpin,
{
    let reply = TunnelOpened {
        kind: "tunnel.opened",
    };
    let bytes = serde_json::to_vec(&reply)?;
    send_encrypted_bytes(transport, ws_sink, &bytes).await
}

async fn send_tunnel_error<S>(
    transport: &mut dyn EncryptedTransport,
    ws_sink: &mut S,
    msg: &str,
) -> anyhow::Result<()>
where
    S: futures_util::Sink<Message, Error = hyper_tungstenite::tungstenite::Error> + Unpin,
{
    let err = TunnelError {
        kind: "tunnel.error",
        msg: msg.to_string(),
    };
    let bytes = serde_json::to_vec(&err)?;
    send_encrypted_bytes(transport, ws_sink, &bytes).await
}

async fn handle_standalone<S>(
    req: &KawiriRequest,
    is_stream: bool,
    transport: &mut dyn EncryptedTransport,
    ws_sink: &mut S,
) -> anyhow::Result<()>
where
    S: futures_util::Sink<Message, Error = hyper_tungstenite::tungstenite::Error> + Unpin,
{
    if is_stream {
        let chunk = KawiriStreamChunk {
            id: req.id,
            event: "data".into(),
            data: Some(serde_json::json!({
                "choices": [{"delta": {"content": "Hello from kawa standalone"}}]
            })),
        };
        send_encrypted_chunk(transport, ws_sink, &chunk).await?;

        let done = KawiriStreamChunk {
            id: req.id,
            event: "done".into(),
            data: None,
        };
        send_encrypted_chunk(transport, ws_sink, &done).await?;
    } else {
        let resp = KawiriResponse {
            id: req.id,
            status: 200,
            body: Some(serde_json::json!({
                "choices": [{"message": {"content": "Hello from kawa standalone"}}]
            })),
        };
        send_encrypted_response(transport, ws_sink, &resp).await?;
    }

    Ok(())
}

// ── Boot banner helpers ──────────────────────────────────────────

fn log_system_info(config: &Config, tee_mode: TeeMode) {
    // Kernel
    let kernel = std::fs::read_to_string("/proc/version")
        .ok()
        .and_then(|v| v.split_whitespace().nth(2).map(String::from))
        .unwrap_or_else(|| "unknown".into());

    // CPU count
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0);

    // Memory (from /proc/meminfo, first line: "MemTotal:  ... kB")
    let mem = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|m| {
            let kb: u64 = m.lines().next()?.split_whitespace().nth(1)?.parse().ok()?;
            Some(format!("{:.1} GB", kb as f64 / 1_048_576.0))
        })
        .unwrap_or_else(|| "unknown".into());

    info!("kawa v{}", env!("CARGO_PKG_VERSION"));
    info!("kernel={kernel} vcpus={cpus} memory={mem}");
    let tunnel_summary = if config.tunnel_ports.is_empty() {
        "off".to_string()
    } else {
        config
            .tunnel_ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",")
    };
    info!(
        "mode={} pq={} port={} attestation={} tunnels={}",
        if config.is_standalone() {
            "standalone"
        } else {
            "proxy"
        },
        config.enable_pq,
        config.port,
        match tee_mode {
            TeeMode::Real => "real",
            TeeMode::Mock => "MOCK",
        },
        tunnel_summary,
    );
}

fn log_attestation(payload: &crate::protocol::types::AttestationPayload) {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    info!("platform: {}", payload.platform);

    let quote_bytes = match payload.quote.as_ref() {
        Some(b64) => match STANDARD.decode(b64) {
            Ok(bytes) => bytes,
            Err(_) => return,
        },
        None => {
            info!("quote: none (mock)");
            return;
        }
    };

    info!("quote: {} bytes", quote_bytes.len());

    let hex = |data: &[u8], offset: usize, len: usize| -> String {
        match data.get(offset..offset + len) {
            Some(slice) => slice.iter().map(|b| format!("{b:02x}")).collect(),
            None => "<out of bounds>".into(),
        }
    };

    if payload.platform == "TDX" {
        if quote_bytes.len() >= TDX_MIN_LEN {
            info!("MRTD:  {}", hex(&quote_bytes, TDX_MRTD, 48));
            info!("RTMR0: {}", hex(&quote_bytes, TDX_RTMR0, 48));
            info!("RTMR1: {}", hex(&quote_bytes, TDX_RTMR1, 48));
            info!("RTMR2: {}", hex(&quote_bytes, TDX_RTMR2, 48));
            info!("RTMR3: {}", hex(&quote_bytes, TDX_RTMR3, 48));
        }
    } else if payload.platform == "SEV-SNP" && quote_bytes.len() >= SNP_MIN_LEN {
        info!("launch digest: {}", hex(&quote_bytes, SNP_MEASUREMENT, 48));
        info!("report data:   {}", hex(&quote_bytes, SNP_REPORT_DATA, 64));
        info!("host data:     {}", hex(&quote_bytes, SNP_HOST_DATA, 32));
    }
}
