use serde::{Deserialize, Serialize};

/// Client → Server request over encrypted channel.
#[derive(Debug, Deserialize)]
pub struct KawiriRequest {
    pub id: u64,
    pub method: String,
    pub path: String,
    pub body: Option<serde_json::Value>,
}

/// Server → Client non-streaming response.
#[derive(Debug, Serialize)]
pub struct KawiriResponse {
    pub id: u64,
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<serde_json::Value>,
}

/// Server → Client streaming chunk.
#[derive(Debug, Serialize)]
pub struct KawiriStreamChunk {
    pub id: u64,
    pub event: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// TEE attestation payload sent in Noise handshake message 1.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationPayload {
    pub platform: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quote: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_chain: Option<String>,
    pub nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_bundle: Option<String>,
    /// GPU CC attestation evidence (one per GPU with CC enabled).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpu_evidence: Option<Vec<crate::tee::gpu_attest::GpuEvidence>>,
}

/// XWing upgrade message 1: server → client.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct XWingUpgradeMsg1 {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub public_key: String,
}

/// XWing upgrade message 2: client → server.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct XWingUpgradeMsg2 {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub cipher_text: String,
}

// ── Tunnel mode (post-handshake byte relay) ───────────────────────────────
//
// After Noise + (optional) X-Wing upgrade, the first decrypted message
// decides whether this transport is RPC-mode (existing `KawiriRequest`
// chat traffic) or tunnel-mode (opaque byte relay to a loopback port
// inside the CVM). The `kind` field is the discriminator; `KawiriRequest`
// has no `kind`, so legacy clients are unambiguously RPC.
//
// Wire format after `tunnel.opened`:
//   - every WS message is exactly one Noise-encrypted frame
//   - inside the encrypted plaintext: framer single-frame envelope
//     (FLAG_SINGLE byte + payload bytes), no JSON wrapper
//   - chunked frames are forbidden in tunnel mode (frames are capped)
//   - empty payload = half-close marker (sender done writing)

/// First post-handshake message in tunnel mode (client → server).
/// `kind` is required on the wire (it's the discriminator vs KawiriRequest)
/// but unused after dispatch — the peek already established the kind.
#[derive(Debug, Deserialize)]
pub struct TunnelOpen {
    #[allow(dead_code)]
    pub kind: String,
    pub port: u16,
}

/// Server → client success reply.
#[derive(Debug, Serialize)]
pub struct TunnelOpened {
    pub kind: &'static str,
}

/// Server → client failure reply (port not in allowlist, connect refused, etc.).
#[derive(Debug, Serialize)]
pub struct TunnelError {
    pub kind: &'static str,
    pub msg: String,
}

/// Used to peek at the first decrypted message to decide RPC vs tunnel.
/// All fields optional so KawiriRequest payloads don't fail to parse.
#[derive(Debug, Deserialize)]
pub struct FirstMessagePeek {
    #[serde(default)]
    pub kind: Option<String>,
}
