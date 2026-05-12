//! Cleartext stats events emitted by kawa.
//!
//! This module is the **single privacy boundary** for what escapes the
//! TEE as cleartext metadata about a request. Everything kawa serializes
//! for outside consumption goes through here:
//!
//!   - In-stream meta (envelope sent over the encrypted WS so the
//!     browser can render usage live) — [`Stats`] + [`ChunkMeta`].
//!   - Out-of-stream stats (vsock push to teehost, decorated and
//!     persisted to disk; see `kawa/src/stats_vsock.rs` and the
//!     `teehost::kawa_stats` module) — same [`Stats`] type.
//!
//! An auditor who only reads this file should be able to convince
//! themselves that no user prompt content and no model output content
//! can reach any external consumer.
//!
//! ## What can appear in a Stats record
//!
//! - **Counts** (`u32`, `u64`) — number of tokens, number of bytes,
//!   number of milliseconds. A count is structurally incapable of
//!   encoding a prompt.
//! - **Categorical strings** (`&'static str` or whitelist-matched
//!   `String`) — values drawn from a closed set defined in this file.
//!   Free-form upstream strings are NEVER promoted into a Stats record;
//!   they are mapped to a `&'static str` constant via [`classify_error`]
//!   and the original message is dropped.
//! - **Caller-supplied identifiers** the consumer already saw — the
//!   model name (which was a URL/body parameter that selected this VM)
//!   and the request id (a caller-chosen integer).
//! - **Engine-specific numeric measurements** — e.g. llama.cpp's
//!   `timings` block. These are read into a typed struct ([`EngineStats`])
//!   whose fields are exclusively numeric, so no engine-side string
//!   accident can leak content through.
//!
//! ## What can NEVER appear
//!
//! - Bytes from `delta.content` or `delta.reasoning_content`.
//! - Bytes from `messages[].content` (the user's prompt).
//! - The text of any upstream error message — only its category.
//! - Tool-call arguments, system prompts, citations, attachments.
//!
//! All functions in this module are pure: no I/O, no logging, no global
//! state. The only way a Stats record becomes externally observable is
//! when the caller serializes it through one of the wire paths.

use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Token usage counts. Pure numbers — no content.
#[derive(Debug, Clone, serde::Serialize)]
pub struct UsageCounts {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completion_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_tokens: Option<u64>,
}

/// End-of-request stats record. Produced exactly once per request by
/// [`StatsBuilder::finalize`]. Sent both:
/// - in-stream as the pure-meta envelope at end-of-stream (so konnect /
///   the browser can show usage live), and
/// - out-of-stream via vsock to teehost for persistence (so the host
///   can do billing/quota/audit).
///
/// Both paths serialize the same JSON; teehost adds `vm_id`,
/// `image_name`, `host_id`, `user_id`, `token_id`, and `ingested_at_ms`
/// at ingest time — kawa never emits those fields.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Stats {
    /// Schema discriminator — always `"kawiri.stats"`.
    pub object: &'static str,
    /// Schema generation. Bump on any incompatible field change.
    pub schema_version: u32,
    /// Caller's request id. Just a number; downstream uses it to
    /// correlate billing rows.
    pub req_id: u64,
    /// Wall-clock unix epoch milliseconds when kawa started handling
    /// the request. Distinct from `duration_ms` (monotonic).
    pub started_at_ms: u64,
    /// Wall-clock duration of the request, milliseconds.
    pub duration_ms: u64,
    /// Model name from the request body. Already disclosed via the
    /// `?model=` URL parameter that selected this VM, so echoing it
    /// adds no new information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Authoritative usage counts as reported by the inference engine.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<UsageCounts>,
    /// Engine-specific numeric measurements (currently llama.cpp
    /// timings). Typed by engine so no engine-side string can ride
    /// along.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine: Option<EngineStats>,
    /// OpenAI-spec finish_reason. Always one of [`FINISH_REASONS`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finish_reason: Option<String>,
    /// `"ok"` on success, `"error"` on any failure.
    pub status: &'static str,
    /// Categorical error label when `status == "error"`. One of
    /// [`ERROR_KINDS`]; never the upstream error message itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<&'static str>,
}

/// Per-chunk in-stream envelope. Sent alongside a streaming response
/// chunk over the encrypted WS (the wire envelope's `data` slot
/// carries the encrypted chunk, the `meta` slot carries this).
///
/// Exactly one of `delta_bytes` or `usage` is set, never both:
/// - `usage` — authoritative running counts from the engine.
/// - `delta_bytes` — UTF-8 byte length of new content added by this
///   chunk; coarse progress only, **not a token count**.
///
/// Distinct from [`Stats`]: [`ChunkMeta`] is per-chunk live progress;
/// [`Stats`] is the per-request authoritative summary at end-of-stream.
#[derive(Debug, serde::Serialize)]
pub struct ChunkMeta {
    /// Schema discriminator — always `"kawiri.chunk"`.
    pub object: &'static str,
    /// Request id this chunk belongs to.
    pub req_id: u64,
    /// UTF-8 byte count of new model output in this chunk.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta_bytes: Option<u32>,
    /// Authoritative running counts from upstream.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<UsageCounts>,
}

/// Engine-specific stats, tagged by engine kind. All variants hold
/// numeric-only fields — a strict structural guarantee that engine
/// strings (model names, internal status, etc.) can't accidentally
/// promote into a Stats envelope.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum EngineStats {
    /// llama.cpp `timings` block, as emitted by llama-server when the
    /// final SSE chunk includes `"timings": { ... }`.
    Llamacpp(LlamaCppTimings),
}

/// Subset of llama.cpp's `timings` block we pass through. Pure numbers
/// — no strings.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct LlamaCppTimings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub predicted_n: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub predicted_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub predicted_per_token_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub predicted_per_second: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_n: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_per_token_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_per_second: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_n: Option<u64>,
}

/// Closed set of OpenAI-spec `finish_reason` values we promote into a
/// Stats record. Any other string from upstream is silently dropped.
pub const FINISH_REASONS: &[&str] = &[
    "stop",
    "length",
    "tool_calls",
    "content_filter",
    "function_call",
];

/// Closed set of error labels. The original upstream error message is
/// mapped to one of these by [`classify_error`] and the text is
/// discarded. Exposed so an auditor can grep for the complete set of
/// strings that may appear in `Stats::error_kind`; asserted in tests.
#[allow(dead_code)]
pub const ERROR_KINDS: &[&str] = &["context_overflow", "timeout", "upstream_error", "internal"];

/// Per-request accumulator. Builds state as chunks arrive; on finish,
/// produces the [`Stats`] for the end-of-request record.
///
/// Pure data: no I/O, no logging, no global state. The only inputs are
/// typed values — even the `&str` taken by [`Self::ingest_error`] is
/// read-only and the function returns nothing that contains it.
#[derive(Debug)]
pub struct StatsBuilder {
    req_id: u64,
    model: Option<String>,
    started_at_ms: u64,
    started: Instant,
    usage: Option<UsageCounts>,
    engine: Option<EngineStats>,
    finish_reason: Option<String>,
    error_kind: Option<&'static str>,
}

impl StatsBuilder {
    pub fn new(req_id: u64, model: Option<String>) -> Self {
        let started_at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        Self {
            req_id,
            model,
            started_at_ms,
            started: Instant::now(),
            usage: None,
            engine: None,
            finish_reason: None,
            error_kind: None,
        }
    }

    /// Read counts and the whitelisted `finish_reason` out of a parsed
    /// streaming chunk's JSON. Never clones content strings. Picks up
    /// engine timings if the chunk carries them (typically only on the
    /// final reconciliation chunk for llama.cpp).
    pub fn ingest_chunk(&mut self, parsed: &serde_json::Value) {
        if let Some(u) = extract_usage(parsed) {
            self.usage = Some(u);
        }
        if let Some(e) = extract_engine(parsed) {
            self.engine = Some(e);
        }
        if let Some(fr) = parsed
            .get("choices")
            .and_then(|c| c.get(0))
            .and_then(|c| c.get("finish_reason"))
            .and_then(|v| v.as_str())
        {
            // Whitelist match — a free-form string from a buggy or
            // adversarial upstream cannot promote arbitrary text into
            // the stats record.
            if FINISH_REASONS.contains(&fr) {
                self.finish_reason = Some(fr.to_string());
            }
        }
    }

    /// Read counts out of a non-streaming response body.
    pub fn ingest_response_body(&mut self, body: &serde_json::Value) {
        if let Some(u) = extract_usage(body) {
            self.usage = Some(u);
        }
        if let Some(e) = extract_engine(body) {
            self.engine = Some(e);
        }
        if let Some(fr) = body
            .get("choices")
            .and_then(|c| c.get(0))
            .and_then(|c| c.get("finish_reason"))
            .and_then(|v| v.as_str())
        {
            if FINISH_REASONS.contains(&fr) {
                self.finish_reason = Some(fr.to_string());
            }
        }
    }

    /// Record that the request errored. The upstream message text is
    /// intentionally dropped; only the categorical [`classify_error`]
    /// return value survives.
    pub fn ingest_error(&mut self, upstream_message: &str) {
        self.error_kind = Some(classify_error(upstream_message));
    }

    /// Produce the end-of-request envelope.
    pub fn finalize(self) -> Stats {
        Stats {
            object: "kawiri.stats",
            schema_version: 1,
            req_id: self.req_id,
            started_at_ms: self.started_at_ms,
            duration_ms: self.started.elapsed().as_millis() as u64,
            model: self.model,
            usage: self.usage,
            engine: self.engine,
            finish_reason: self.finish_reason,
            status: if self.error_kind.is_some() {
                "error"
            } else {
                "ok"
            },
            error_kind: self.error_kind,
        }
    }
}

/// Build the per-chunk in-stream meta envelope for a streaming response
/// chunk. Returns `None` when the chunk has nothing worth metering.
///
/// Decision order:
///   1. If the chunk has a `usage` block, pass it through authoritatively.
///   2. Otherwise, if the chunk extends model output, report the UTF-8
///      byte length of the new content as a coarse progress signal.
///   3. Otherwise, return `None`.
pub fn chunk_meta_for(req_id: u64, parsed: &serde_json::Value) -> Option<ChunkMeta> {
    if let Some(u) = extract_usage(parsed) {
        return Some(ChunkMeta {
            object: "kawiri.chunk",
            req_id,
            delta_bytes: None,
            usage: Some(u),
        });
    }
    let bytes = delta_bytes_for(parsed);
    if bytes > 0 {
        return Some(ChunkMeta {
            object: "kawiri.chunk",
            req_id,
            delta_bytes: Some(bytes),
            usage: None,
        });
    }
    None
}

/// Sum the UTF-8 byte length of `delta.content` and
/// `delta.reasoning_content`. Reads strings only to measure their
/// length — the bytes are never copied out.
fn delta_bytes_for(parsed: &serde_json::Value) -> u32 {
    let delta = parsed
        .get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("delta"));
    let mut total: u32 = 0;
    for field in ["content", "reasoning_content"] {
        if let Some(s) = delta.and_then(|d| d.get(field)).and_then(|v| v.as_str()) {
            let len = u32::try_from(s.len()).unwrap_or(u32::MAX);
            total = total.saturating_add(len);
        }
    }
    total
}

/// Pull the `usage` block out of a parsed value (chunk or full response
/// body). Reads only `u64` count fields.
fn extract_usage(parsed: &serde_json::Value) -> Option<UsageCounts> {
    let u = parsed.get("usage")?;
    if u.is_null() {
        return None;
    }
    Some(UsageCounts {
        prompt_tokens: u.get("prompt_tokens").and_then(|v| v.as_u64()),
        completion_tokens: u.get("completion_tokens").and_then(|v| v.as_u64()),
        total_tokens: u.get("total_tokens").and_then(|v| v.as_u64()),
    })
}

/// Detect and extract engine-specific timings from a parsed chunk or
/// response body. Currently recognizes llama.cpp's `timings` block.
/// Each field is type-checked individually — anything non-numeric is
/// dropped, so no engine-side surprise can promote a string into the
/// record.
fn extract_engine(parsed: &serde_json::Value) -> Option<EngineStats> {
    let t = parsed.get("timings")?;
    if t.is_null() {
        return None;
    }
    Some(EngineStats::Llamacpp(LlamaCppTimings {
        predicted_n: t.get("predicted_n").and_then(|v| v.as_u64()),
        predicted_ms: t.get("predicted_ms").and_then(|v| v.as_f64()),
        predicted_per_token_ms: t.get("predicted_per_token_ms").and_then(|v| v.as_f64()),
        predicted_per_second: t.get("predicted_per_second").and_then(|v| v.as_f64()),
        prompt_n: t.get("prompt_n").and_then(|v| v.as_u64()),
        prompt_ms: t.get("prompt_ms").and_then(|v| v.as_f64()),
        prompt_per_token_ms: t.get("prompt_per_token_ms").and_then(|v| v.as_f64()),
        prompt_per_second: t.get("prompt_per_second").and_then(|v| v.as_f64()),
        cache_n: t.get("cache_n").and_then(|v| v.as_u64()),
    }))
}

/// Set `stream_options.include_usage = true` and `.continuous_usage_stats
/// = true` on a chat-completion request body so kawa can reliably
/// extract token counts.
///
/// Mutates ONLY the `stream_options` sub-object. Does not read, copy,
/// or modify any other field of the body.
pub fn inject_usage_flags(body: &mut serde_json::Value) {
    let Some(obj) = body.as_object_mut() else {
        return;
    };
    let entry = obj
        .entry("stream_options")
        .or_insert(serde_json::Value::Object(serde_json::Map::new()));
    if let Some(opts) = entry.as_object_mut() {
        opts.insert("include_usage".into(), serde_json::Value::Bool(true));
        opts.insert(
            "continuous_usage_stats".into(),
            serde_json::Value::Bool(true),
        );
    }
}

/// Map a free-form upstream error message to a closed set of categorical
/// labels. The original message is NOT returned. Pattern order is
/// most-specific to most-generic.
pub fn classify_error(message: &str) -> &'static str {
    let lower = message.to_ascii_lowercase();
    if lower.contains("timeout") || lower.contains("deadline") {
        "timeout"
    } else if lower.contains("connection")
        || lower.contains("upstream")
        || lower.contains("refused")
        || lower.contains("error sending request")
    {
        "upstream_error"
    } else if lower.contains("context")
        || lower.contains("token limit")
        || lower.contains("too long")
    {
        "context_overflow"
    } else {
        "internal"
    }
}

// ── vsock egress to teehost ──────────────────────────────────────────────
//
// The second emit path: kawa pushes a finalized Stats record over vsock
// to teehost for persistence + aggregation. Fire-and-forget — failures
// degrade observability, never the request itself. Teehost runs the
// `kawa_stats` listener on the same vsock port as the rest of the
// kawa↔teehost protocol (see kcvm/tee/vsock_teehost.rs); we add a new
// message type kind without disturbing the existing PING / GET_SNP_CERTS
// roundtrips.

mod vsock_wire {
    //! Constants in lockstep with `teehost/src/kawa_stats/proto.rs`.
    /// Host CID (every CVM sees the host as 2).
    pub const HOST_CID: u32 = 2;
    /// teehost vsock port (shared with the existing kawa↔teehost protocol).
    pub const TEEHOST_PORT: u32 = 4050;
    pub const MAJOR_VERSION: u16 = 1;
    pub const MINOR_VERSION: u16 = 1;
    pub const HEADER_SIZE: usize = 16;
    /// New message type for kawa→teehost stats reports. Existing kinds
    /// (PING_REQ=130, PING_RESP=131, GET_SNP_CERTS_REQ=128,
    /// GET_SNP_CERTS_RESP=129) stay unchanged.
    pub const KAWA_STATS_REPORT: u32 = 140;
}

/// Build a framed `KAWA_STATS_REPORT` packet:
///   [4-byte BE total_size] [header(16)] [JSON body]
/// where the header is `[u16 major][u16 minor][u32 msg_type][u32
/// total_size][u32 error_code=0]` little-endian. Same wire format as
/// the existing kawa↔teehost protocol.
fn build_stats_frame(payload: &[u8]) -> Vec<u8> {
    let total_size = (vsock_wire::HEADER_SIZE + payload.len()) as u32;
    let mut buf = Vec::with_capacity(4 + total_size as usize);
    buf.extend_from_slice(&total_size.to_be_bytes());
    buf.extend_from_slice(&vsock_wire::MAJOR_VERSION.to_le_bytes());
    buf.extend_from_slice(&vsock_wire::MINOR_VERSION.to_le_bytes());
    buf.extend_from_slice(&vsock_wire::KAWA_STATS_REPORT.to_le_bytes());
    buf.extend_from_slice(&total_size.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // error_code
    buf.extend_from_slice(payload);
    buf
}

/// Errors that can stop a stats push. None of these tear down a
/// request — the caller is expected to log + carry on.
#[derive(Debug, thiserror::Error)]
pub enum StatsSendError {
    #[error("vsock I/O: {0}")]
    Io(std::io::Error),
    #[error("connect or write timed out")]
    Timeout,
    #[error("serialize stats: {0}")]
    Serialize(serde_json::Error),
}

/// Push one Stats record to teehost via vsock. Fire-and-forget: opens
/// a connection, writes the framed payload, closes. Never reads a
/// response (teehost acknowledges by ingesting; loss surfaces as a
/// gap in the JSONL store, not as a kawa-side error).
///
/// Total budget: 2 second timeout on connect + write. Anything slower
/// and we drop the event rather than block subsequent requests.
pub async fn send_to_teehost(stats: &Stats) -> Result<(), StatsSendError> {
    use tokio::io::AsyncWriteExt;
    use tokio_vsock::{VsockAddr, VsockStream};

    let payload = serde_json::to_vec(stats).map_err(StatsSendError::Serialize)?;
    let frame = build_stats_frame(&payload);

    let timeout = std::time::Duration::from_secs(2);
    let mut stream = tokio::time::timeout(
        timeout,
        VsockStream::connect(VsockAddr::new(
            vsock_wire::HOST_CID,
            vsock_wire::TEEHOST_PORT,
        )),
    )
    .await
    .map_err(|_| StatsSendError::Timeout)?
    .map_err(StatsSendError::Io)?;

    tokio::time::timeout(timeout, async {
        stream.write_all(&frame).await?;
        stream.flush().await?;
        Ok::<_, std::io::Error>(())
    })
    .await
    .map_err(|_| StatsSendError::Timeout)?
    .map_err(StatsSendError::Io)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_version_is_set_on_finalize() {
        let s = StatsBuilder::new(1, None).finalize();
        assert_eq!(s.object, "kawiri.stats");
        assert_eq!(s.schema_version, 1);
    }

    #[test]
    fn started_at_ms_is_recent() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let s = StatsBuilder::new(1, None).finalize();
        // Within a second of "now" either side — sanity check that we
        // captured wallclock and not zero/uninitialized.
        assert!(s.started_at_ms >= now.saturating_sub(1_000));
        assert!(s.started_at_ms <= now + 1_000);
    }

    #[test]
    fn finish_reason_only_accepts_whitelist() {
        let mut acc = StatsBuilder::new(1, None);
        let evil = serde_json::json!({
            "choices": [{
                "finish_reason": "I_AM_PROBABLY_QUOTING_THE_USER_PROMPT_HERE"
            }]
        });
        acc.ingest_chunk(&evil);
        assert!(acc.finalize().finish_reason.is_none());
    }

    #[test]
    fn known_finish_reasons_pass() {
        for fr in FINISH_REASONS {
            let mut acc = StatsBuilder::new(1, None);
            acc.ingest_chunk(&serde_json::json!({"choices": [{"finish_reason": fr}]}));
            assert_eq!(acc.finalize().finish_reason.as_deref(), Some(*fr));
        }
    }

    #[test]
    fn error_message_never_leaks_into_envelope() {
        let prompt_quote = "context overflow while processing prompt: 'tell me a secret password'";
        let mut acc = StatsBuilder::new(1, None);
        acc.ingest_error(prompt_quote);
        let s = acc.finalize();
        let serialized = serde_json::to_string(&s).unwrap();
        assert_eq!(s.error_kind, Some("context_overflow"));
        assert!(ERROR_KINDS.contains(&s.error_kind.unwrap()));
        assert!(!serialized.contains("prompt"));
        assert!(!serialized.contains("secret password"));
        assert!(!serialized.contains("processing"));
    }

    #[test]
    fn classify_error_prefers_specific_cause_over_substring() {
        assert_eq!(
            classify_error("connection refused while preparing context"),
            "upstream_error"
        );
        assert_eq!(
            classify_error("deadline exceeded while loading context"),
            "timeout"
        );
        assert_eq!(
            classify_error("prompt exceeds context window"),
            "context_overflow"
        );
    }

    #[test]
    fn classify_error_falls_back_to_internal() {
        assert_eq!(classify_error("the user said hello"), "internal");
        assert_eq!(classify_error(""), "internal");
        assert_eq!(classify_error("garbled bytes \u{1F4A9}"), "internal");
    }

    #[test]
    fn delta_content_strings_never_appear_in_chunk_meta() {
        let secret = "MY_SECRET_API_KEY_sk-abc123def456";
        let chunk = serde_json::json!({
            "choices": [{ "delta": {"content": secret} }]
        });
        let cm = chunk_meta_for(7, &chunk).unwrap();
        let serialized = serde_json::to_string(&cm).unwrap();
        assert!(!serialized.contains("MY_SECRET"));
        assert!(!serialized.contains("sk-"));
        assert_eq!(cm.delta_bytes, Some(secret.len() as u32));
        assert!(cm.usage.is_none());
        assert_eq!(cm.req_id, 7);
        assert_eq!(cm.object, "kawiri.chunk");
    }

    #[test]
    fn authoritative_usage_takes_priority_over_heuristic() {
        let chunk = serde_json::json!({
            "choices": [{"delta": {"content": "hello"}}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 1, "total_tokens": 6}
        });
        let cm = chunk_meta_for(99, &chunk).unwrap();
        assert!(cm.delta_bytes.is_none(), "should defer to authoritative");
        let u = cm.usage.unwrap();
        assert_eq!(u.prompt_tokens, Some(5));
        assert_eq!(u.completion_tokens, Some(1));
        assert_eq!(cm.req_id, 99);
    }

    #[test]
    fn empty_delta_emits_nothing() {
        assert!(chunk_meta_for(1, &serde_json::json!({})).is_none());
        assert!(chunk_meta_for(
            1,
            &serde_json::json!({"choices":[{"delta":{"role":"assistant"}}]})
        )
        .is_none());
        assert!(chunk_meta_for(
            1,
            &serde_json::json!({"choices":[{"delta":{"content":""}}]})
        )
        .is_none());
    }

    #[test]
    fn reasoning_content_counts_too() {
        let chunk = serde_json::json!({
            "choices": [{"delta": {"reasoning_content": "thinking..."}}]
        });
        let cm = chunk_meta_for(1, &chunk).unwrap();
        assert_eq!(cm.delta_bytes, Some("thinking...".len() as u32));
    }

    #[test]
    fn delta_bytes_sums_content_and_reasoning() {
        let chunk = serde_json::json!({
            "choices": [{"delta": {
                "content": "abc",
                "reasoning_content": "wxyz",
            }}]
        });
        let cm = chunk_meta_for(1, &chunk).unwrap();
        assert_eq!(cm.delta_bytes, Some(3 + 4));
    }

    #[test]
    fn delta_bytes_counts_utf8_bytes_not_codepoints() {
        let s = "héllo🎉"; // 1 + 2 + 3*1 + 4 = 10 bytes
        assert_eq!(s.len(), 10);
        let chunk = serde_json::json!({"choices":[{"delta":{"content": s}}]});
        let cm = chunk_meta_for(1, &chunk).unwrap();
        assert_eq!(cm.delta_bytes, Some(10));
    }

    #[test]
    fn inject_usage_flags_sets_both() {
        let mut body = serde_json::json!({
            "model": "qwen3",
            "messages": [{"role": "user", "content": "hello"}],
            "max_tokens": 100,
        });
        inject_usage_flags(&mut body);
        let opts = body.get("stream_options").unwrap().as_object().unwrap();
        assert_eq!(
            opts.get("include_usage"),
            Some(&serde_json::Value::Bool(true))
        );
        assert_eq!(
            opts.get("continuous_usage_stats"),
            Some(&serde_json::Value::Bool(true))
        );
        assert_eq!(body.get("model").unwrap(), "qwen3");
        assert_eq!(
            body.get("messages").unwrap()[0].get("content").unwrap(),
            "hello"
        );
        assert_eq!(body.get("max_tokens").unwrap(), 100);
    }

    #[test]
    fn inject_usage_flags_preserves_existing_options() {
        let mut body = serde_json::json!({
            "stream_options": {"some_future_flag": "preserved"}
        });
        inject_usage_flags(&mut body);
        let opts = body.get("stream_options").unwrap().as_object().unwrap();
        assert_eq!(
            opts.get("some_future_flag"),
            Some(&serde_json::Value::String("preserved".into()))
        );
        assert_eq!(
            opts.get("include_usage"),
            Some(&serde_json::Value::Bool(true))
        );
    }

    #[test]
    fn inject_usage_flags_noop_on_non_object() {
        let mut body = serde_json::json!("a string");
        inject_usage_flags(&mut body);
        assert_eq!(body, serde_json::json!("a string"));
    }

    #[test]
    fn finalize_status_reflects_error_state() {
        let mut acc = StatsBuilder::new(42, Some("qwen3".into()));
        acc.ingest_error("connection refused by upstream");
        let s = acc.finalize();
        assert_eq!(s.status, "error");
        assert_eq!(s.error_kind, Some("upstream_error"));
        assert_eq!(s.req_id, 42);
        assert_eq!(s.model.as_deref(), Some("qwen3"));
    }

    // ── Engine extraction tests ────────────────────────────────────

    #[test]
    fn llamacpp_timings_extracted_when_present() {
        let mut acc = StatsBuilder::new(1, None);
        acc.ingest_chunk(&serde_json::json!({
            "choices": [],
            "timings": {
                "predicted_n": 200,
                "predicted_ms": 4900.5,
                "predicted_per_second": 40.8,
                "prompt_n": 50,
                "prompt_ms": 800.0,
                "cache_n": 32
            }
        }));
        let s = acc.finalize();
        match s.engine.expect("engine should be set") {
            EngineStats::Llamacpp(t) => {
                assert_eq!(t.predicted_n, Some(200));
                assert_eq!(t.predicted_ms, Some(4900.5));
                assert_eq!(t.predicted_per_second, Some(40.8));
                assert_eq!(t.prompt_n, Some(50));
                assert_eq!(t.prompt_ms, Some(800.0));
                assert_eq!(t.cache_n, Some(32));
            }
        }
    }

    #[test]
    fn llamacpp_timings_drops_non_numeric_fields() {
        // If the engine ever decides to put a string in a numeric field
        // (or smuggles one in), our serde extraction returns None for
        // that field rather than passing the string through. Privacy
        // guarantee even against a buggy / hostile engine.
        let mut acc = StatsBuilder::new(1, None);
        acc.ingest_chunk(&serde_json::json!({
            "timings": {
                "predicted_n": "200; DROP TABLE users;--",   // string in u64 slot
                "predicted_ms": 4900.5,
                "system_note": "internal error: prompt was 'tell me a secret'"
            }
        }));
        let s = acc.finalize();
        let serialized = serde_json::to_string(&s).unwrap();
        assert!(!serialized.contains("DROP TABLE"));
        assert!(!serialized.contains("system_note"));
        assert!(!serialized.contains("secret"));
        // The valid numeric field still made it through.
        assert!(serialized.contains("4900.5"));
    }

    #[test]
    fn no_engine_block_when_timings_absent() {
        let mut acc = StatsBuilder::new(1, None);
        acc.ingest_chunk(&serde_json::json!({
            "choices": [{"delta": {"content": "hi"}}]
        }));
        assert!(acc.finalize().engine.is_none());
    }

    // ── Vsock framing tests ───────────────────────────────────────

    #[test]
    fn stats_frame_layout_is_correct() {
        // Smoke-check the exact byte layout against the documented wire
        // format: [u32 BE total][u16 LE major][u16 LE minor]
        //         [u32 LE type][u32 LE total][u32 LE error=0][body…]
        let body = b"hello";
        let frame = build_stats_frame(body);

        let expected_total = (vsock_wire::HEADER_SIZE + body.len()) as u32;
        assert_eq!(
            &frame[0..4],
            &expected_total.to_be_bytes(),
            "BE length prefix"
        );
        assert_eq!(
            &frame[4..6],
            &vsock_wire::MAJOR_VERSION.to_le_bytes(),
            "LE major"
        );
        assert_eq!(
            &frame[6..8],
            &vsock_wire::MINOR_VERSION.to_le_bytes(),
            "LE minor"
        );
        assert_eq!(
            &frame[8..12],
            &vsock_wire::KAWA_STATS_REPORT.to_le_bytes(),
            "LE msg_type"
        );
        assert_eq!(
            &frame[12..16],
            &expected_total.to_le_bytes(),
            "LE total_size"
        );
        assert_eq!(&frame[16..20], &0u32.to_le_bytes(), "error_code = 0");
        assert_eq!(&frame[20..], body, "body verbatim");
        assert_eq!(
            frame.len(),
            4 + vsock_wire::HEADER_SIZE + body.len(),
            "total frame length"
        );
    }

    #[test]
    fn stats_frame_serializes_a_real_stats_record() {
        let stats = StatsBuilder::new(42, Some("qwen3".into())).finalize();
        let payload = serde_json::to_vec(&stats).unwrap();
        let frame = build_stats_frame(&payload);
        // Round-trip the header back to make sure msg_type made it
        // through. (We don't need to parse the body here — tests above
        // cover that side.)
        let msg_type = u32::from_le_bytes(frame[8..12].try_into().unwrap());
        assert_eq!(msg_type, 140);
        // Body starts at offset 20, contains the JSON we serialized.
        assert_eq!(&frame[20..], payload.as_slice());
    }
}
