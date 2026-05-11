//! Cleartext metering envelopes that leave the TEE.
//!
//! This module is the **single privacy boundary** for what the router
//! gets to read. Everything that escapes the TEE in cleartext goes
//! through here; the rest of kawa never serializes anything else for
//! external consumption. An auditor who only reads this file should
//! be able to convince themselves that no user prompt content and no
//! model output content can reach the router.
//!
//! ## What can appear in a Meta envelope
//!
//! - **Counts** (`u32`, `u64`) — number of tokens, number of bytes,
//!   number of milliseconds. A count is structurally incapable of
//!   encoding a prompt.
//! - **Categorical strings** (`&'static str` or whitelist-matched
//!   `String`) — values drawn from a closed set defined in this
//!   file. Free-form upstream strings are NEVER promoted into meta;
//!   they are mapped to a `&'static str` constant via
//!   [`classify_error`] and the original message is dropped.
//! - **Caller-supplied identifiers** the router already saw — the
//!   model name (which was a URL parameter that selected this VM)
//!   and the request id (a caller-chosen integer). Echoing these
//!   adds no new disclosure.
//!
//! ## What can NEVER appear
//!
//! - Bytes from `delta.content` or `delta.reasoning_content` (the
//!   model's streamed tokens).
//! - Bytes from the request's `messages[].content` (the user's
//!   prompt).
//! - The text of any upstream error message — only its category.
//! - Tool-call arguments, system prompts, citations, attachments.
//!
//! ## How the privacy property is enforced structurally
//!
//! - [`UsageCounts`] holds only `Option<u64>` fields. The compiler
//!   guarantees no string can sneak in.
//! - [`Meta`] holds only counts, `&'static str`, and `Option<String>`
//!   populated from a whitelist match (`finish_reason`) or from
//!   caller input that's already public (`model`).
//! - [`Accumulator::ingest_chunk`] reads upstream JSON via untyped
//!   `serde_json::Value` lookups, extracts only the count fields
//!   and a whitelist-matched `finish_reason`, and *intentionally
//!   does not* clone the content payload.
//! - [`Accumulator::ingest_error`] takes `&str` but discards it; only
//!   the [`classify_error`] return value (a `&'static str` from a
//!   fixed set) survives into the envelope.
//!
//! All functions in this module are pure: no I/O, no logging, no
//! global state. The only way meta becomes externally observable is
//! when the caller serializes the returned [`Meta`] or [`ChunkMeta`]
//! and sends it through the wire-envelope path in `server.rs`.

use std::time::Instant;

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

/// End-of-request meta envelope. Sent once per request, at end-of-
/// stream, as a pure-meta wire frame (data slot empty).
#[derive(Debug, serde::Serialize)]
pub struct Meta {
    /// Schema discriminator — always `"kawiri.usage"`. Lets the
    /// router reject any future envelope kind it doesn't recognize
    /// without misreading the shape.
    pub object: &'static str,
    /// Caller's request id. Just a number; the router uses it to
    /// correlate billing rows.
    pub req_id: u64,
    /// Model name from the request body. Already disclosed to the
    /// router via the `?model=` URL parameter that selected this
    /// VM, so echoing it here adds no new information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Authoritative usage counts as reported by the inference
    /// engine (vLLM continuous mode, or the final-chunk
    /// reconciliation that llama.cpp and MAX produce when
    /// `stream_options.include_usage` is set).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<UsageCounts>,
    /// Wall-clock duration of the request, milliseconds.
    pub duration_ms: u64,
    /// OpenAI-spec finish_reason. Always one of the closed-set
    /// values; see [`FINISH_REASONS`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finish_reason: Option<String>,
    /// `"ok"` on success, `"error"` on any failure.
    pub status: &'static str,
    /// Categorical error label when `status == "error"`. One of
    /// [`ERROR_KINDS`]; never the upstream error message itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<&'static str>,
}

/// Per-chunk meta envelope. Sent alongside a streaming response
/// chunk (the wire envelope's `data` slot carries the encrypted
/// chunk, the `meta` slot carries this).
///
/// Exactly one of `delta_bytes` or `usage` is set, never both:
/// - `usage` — authoritative running counts emitted by the
///   inference engine itself (vLLM `continuous_usage_stats`, or
///   the reconciliation chunk that llama.cpp / MAX emit when
///   `stream_options.include_usage` is set).
/// - `delta_bytes` — UTF-8 byte length of new content this chunk
///   added (`delta.content` + `delta.reasoning_content`). A coarse
///   *progress signal* for engines that don't emit per-chunk
///   usage; **not a token count** and not safe to gate quota on.
///   The router should treat it as a hint and rely on the
///   end-of-stream [`Meta`] for billing.
#[derive(Debug, serde::Serialize)]
pub struct ChunkMeta {
    /// Schema discriminator — always `"kawiri.chunk"`. Lets the
    /// router reject any future envelope kind it doesn't recognize
    /// without misreading the shape.
    pub object: &'static str,
    /// Request id this chunk belongs to. Required so the router
    /// can attribute the chunk to the right billing row even if
    /// kawa ever multiplexes concurrent requests over one socket.
    pub req_id: u64,
    /// UTF-8 byte count of new model output in this chunk, when
    /// upstream did not provide authoritative usage. Capped at
    /// `u32::MAX` via saturating addition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta_bytes: Option<u32>,
    /// Authoritative running counts from upstream.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<UsageCounts>,
}

/// Closed set of OpenAI-spec `finish_reason` values that we are
/// willing to promote into a Meta envelope. Any other string from
/// upstream is silently dropped.
pub const FINISH_REASONS: &[&str] = &[
    "stop",
    "length",
    "tool_calls",
    "content_filter",
    "function_call",
];

/// Closed set of error labels. The original upstream error message
/// is mapped to one of these by [`classify_error`] and the text is
/// discarded. Exposed so an auditor can grep for the complete set
/// of strings that may appear in `Meta::error_kind`; also asserted
/// in the unit tests. Not referenced from non-test code by design —
/// the source-level enumeration is the documentation.
#[allow(dead_code)]
pub const ERROR_KINDS: &[&str] = &["context_overflow", "timeout", "upstream_error", "internal"];

/// Per-request accumulator. Builds state as chunks arrive; on
/// finish, produces the [`Meta`] for the end-of-stream envelope.
///
/// Pure data: no I/O, no logging, no global state. The only inputs
/// are typed values — even the `&str` taken by [`Self::ingest_error`]
/// is read-only and the function returns nothing that contains it.
#[derive(Debug)]
pub struct Accumulator {
    req_id: u64,
    model: Option<String>,
    usage: Option<UsageCounts>,
    finish_reason: Option<String>,
    error_kind: Option<&'static str>,
    started: Instant,
}

impl Accumulator {
    pub fn new(req_id: u64, model: Option<String>) -> Self {
        Self {
            req_id,
            model,
            usage: None,
            finish_reason: None,
            error_kind: None,
            started: Instant::now(),
        }
    }

    /// Read counts and the whitelisted `finish_reason` out of a
    /// parsed streaming chunk's JSON. Never clones content strings.
    pub fn ingest_chunk(&mut self, parsed: &serde_json::Value) {
        if let Some(u) = extract_usage(parsed) {
            self.usage = Some(u);
        }
        if let Some(fr) = parsed
            .get("choices")
            .and_then(|c| c.get(0))
            .and_then(|c| c.get("finish_reason"))
            .and_then(|v| v.as_str())
        {
            // Whitelist match — a free-form string from a buggy or
            // adversarial upstream cannot promote arbitrary text
            // into the meta envelope.
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

    /// Record that the request errored. The upstream message text
    /// is intentionally dropped; only the categorical
    /// [`classify_error`] return value survives.
    pub fn ingest_error(&mut self, upstream_message: &str) {
        self.error_kind = Some(classify_error(upstream_message));
    }

    /// Produce the end-of-request envelope.
    pub fn finalize(self) -> Meta {
        Meta {
            object: "kawiri.usage",
            req_id: self.req_id,
            model: self.model,
            usage: self.usage,
            duration_ms: self.started.elapsed().as_millis() as u64,
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

/// Build the per-chunk meta for a streaming response chunk. Returns
/// `None` when the chunk has nothing worth metering (zero-content
/// chunks, role announcements, etc).
///
/// Decision order:
///   1. If the chunk has a `usage` block (vLLM continuous mode or
///      any engine's final reconciliation), pass it through as
///      authoritative.
///   2. Otherwise, if the chunk extends the model's output, report
///      the UTF-8 byte length of the new content as a coarse
///      *progress signal* (NOT a token count).
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
/// `delta.reasoning_content` for this chunk. Reads strings only to
/// measure their length — the bytes are never copied out. Uses
/// saturating addition so a pathological chunk can't overflow `u32`.
fn delta_bytes_for(parsed: &serde_json::Value) -> u32 {
    let delta = parsed
        .get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("delta"));
    let mut total: u32 = 0;
    for field in ["content", "reasoning_content"] {
        if let Some(s) = delta.and_then(|d| d.get(field)).and_then(|v| v.as_str()) {
            // `usize as u32` would wrap silently — use saturating.
            let len = u32::try_from(s.len()).unwrap_or(u32::MAX);
            total = total.saturating_add(len);
        }
    }
    total
}

/// Pull the `usage` block out of a parsed value (chunk or full
/// response body). Reads only `u64` count fields.
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

/// Set `stream_options.include_usage = true` and `.continuous_usage_stats
/// = true` on a chat-completion request body so kawa can reliably extract
/// token counts for the meta envelope.
///
/// - `include_usage` (OpenAI spec; honored by llama.cpp and Mojo MAX):
///   adds a final SSE chunk with `usage = {...}` and empty `choices`.
/// - `continuous_usage_stats` (vLLM extension): adds running `usage`
///   counts to every SSE chunk.
///
/// Setting both unconditionally is safe — each engine silently ignores
/// the flag it doesn't recognize. We do this server-side rather than
/// trusting clients to set the flag, because billing accuracy depends
/// on it.
///
/// Mutates ONLY the `stream_options` sub-object. Does not read, copy,
/// or modify any other field of the body — `messages` (user prompts),
/// `model`, `max_tokens`, etc. all pass through untouched.
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

/// Map a free-form upstream error message to a closed set of
/// categorical labels. Matching is intentionally narrow — when in
/// doubt, fall back to `"internal"` rather than letting any unknown
/// pattern slip through. The original message is NOT returned and
/// MUST NOT be serialized into any Meta envelope; operators who
/// need details can read kawa's stderr (which stays inside the TEE).
///
/// Pattern order is most-specific to most-generic, so e.g. a
/// "connection refused" error that incidentally mentions "context"
/// is classified as `upstream_error` (the cause) rather than
/// `context_overflow` (an unrelated substring).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finish_reason_only_accepts_whitelist() {
        let mut acc = Accumulator::new(1, None);
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
            let mut acc = Accumulator::new(1, None);
            acc.ingest_chunk(&serde_json::json!({"choices": [{"finish_reason": fr}]}));
            assert_eq!(acc.finalize().finish_reason.as_deref(), Some(*fr));
        }
    }

    #[test]
    fn error_message_never_leaks_into_envelope() {
        // A pathological upstream error that quotes the user prompt.
        let prompt_quote = "context overflow while processing prompt: 'tell me a secret password'";
        let mut acc = Accumulator::new(1, None);
        acc.ingest_error(prompt_quote);
        let meta = acc.finalize();
        let serialized = serde_json::to_string(&meta).unwrap();
        // Verify the categorical label is set, but no part of the
        // upstream message survives serialization.
        assert_eq!(meta.error_kind, Some("context_overflow"));
        // And the label is one of the known whitelist values — a
        // load-bearing check on ERROR_KINDS itself.
        assert!(ERROR_KINDS.contains(&meta.error_kind.unwrap()));
        assert!(!serialized.contains("prompt"));
        assert!(!serialized.contains("secret password"));
        assert!(!serialized.contains("processing"));
    }

    #[test]
    fn classify_error_prefers_specific_cause_over_substring() {
        // "context" appears, but the underlying cause is upstream — the
        // more specific pattern must win to keep billing labels honest.
        assert_eq!(
            classify_error("connection refused while preparing context"),
            "upstream_error"
        );
        assert_eq!(
            classify_error("deadline exceeded while loading context"),
            "timeout"
        );
        // Pure context error still classifies correctly.
        assert_eq!(
            classify_error("prompt exceeds context window"),
            "context_overflow"
        );
    }

    #[test]
    fn classify_error_falls_back_to_internal() {
        // Unknown patterns must NOT leak through.
        assert_eq!(classify_error("the user said hello"), "internal");
        assert_eq!(classify_error(""), "internal");
        assert_eq!(classify_error("garbled bytes \u{1F4A9}"), "internal");
    }

    #[test]
    fn delta_content_strings_never_appear_in_meta() {
        let secret = "MY_SECRET_API_KEY_sk-abc123def456";
        let chunk = serde_json::json!({
            "choices": [{
                "delta": {"content": secret}
            }]
        });
        let cm = chunk_meta_for(7, &chunk).unwrap();
        let serialized = serde_json::to_string(&cm).unwrap();
        assert!(!serialized.contains("MY_SECRET"));
        assert!(!serialized.contains("sk-"));
        // Length is reported, not content.
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
        // role announcements / empty chunks shouldn't count.
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
        // Some upstreams stream both reasoning and visible content in
        // the same chunk; the byte total must include both.
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
        // A 4-codepoint emoji is 4 UTF-8 bytes. Counting bytes (not
        // chars) is the documented contract — verify it explicitly so
        // the next refactor doesn't accidentally switch to chars().
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
        // Sanity: every OTHER field of the body is untouched.
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
        // Bodies that aren't JSON objects (shouldn't happen in
        // practice but the function must be safe regardless) get
        // silently passed through.
        let mut body = serde_json::json!("a string");
        inject_usage_flags(&mut body);
        assert_eq!(body, serde_json::json!("a string"));
    }

    #[test]
    fn finalize_status_reflects_error_state() {
        let mut acc = Accumulator::new(42, Some("qwen3".into()));
        acc.ingest_error("connection refused by upstream");
        let m = acc.finalize();
        assert_eq!(m.status, "error");
        assert_eq!(m.error_kind, Some("upstream_error"));
        assert_eq!(m.req_id, 42);
        assert_eq!(m.model.as_deref(), Some("qwen3"));
    }
}
