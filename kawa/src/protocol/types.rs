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
