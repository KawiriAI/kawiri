use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use tracing::{debug, info, warn};

use crate::protocol::types::AttestationPayload;

const TSM_REPORT_BASE: &str = "/sys/kernel/config/tsm/report";

/// Cached attestation payload. Real-TEE quotes only depend on report_data
/// (server static key hash, constant per process) and RTMRs (constant at
/// runtime), so we generate once and reuse — configfs-tsm round-trips take
/// ~1s due to firmware latency. Mock payloads are also cached for parity.
static ATTESTATION_CACHE: OnceLock<AttestationPayload> = OnceLock::new();

/// Per-process attestation mode, decided once at startup by [`detect_tee_mode`].
/// Once set, every served handshake serves the same mode for the process'
/// lifetime; that lets clients pin "mock vs real" without surprise.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TeeMode {
    /// configfs-tsm probe succeeded — we'll generate signed quotes from
    /// real SEV-SNP / TDX firmware.
    Real,
    /// configfs-tsm not usable (or `MOCK_TEE` forced). Every attestation
    /// served carries `platform = "mock"` and a deterministic placeholder.
    /// Konnect clients with default `acceptMock = false` will reject.
    Mock,
}

/// Probe whether the kernel actually accepts configfs-tsm report entries.
/// Path-existence alone is too weak — `/sys/kernel/config/tsm/report` can
/// be present with no TSM provider registered, in which case `mkdir` under
/// it returns ENXIO. Doing the same syscall the real handshake does
/// validates the whole pipeline.
pub async fn detect_tee_mode(force_mock: bool) -> TeeMode {
    if force_mock {
        warn!("MOCK_TEE override set — forcing mock attestation regardless of hardware");
        return TeeMode::Mock;
    }
    let probe = format!("{TSM_REPORT_BASE}/kawa_startup_probe");
    match tokio::fs::create_dir(&probe).await {
        Ok(()) => {
            let _ = tokio::fs::remove_dir(&probe).await;
            info!("TEE backing OK ({TSM_REPORT_BASE} accepts report entries) — REAL attestation mode");
            TeeMode::Real
        }
        Err(e) => {
            // Loud warning: every operator/CI viewer should see this in the
            // boot banner. We do NOT fail-fast — the user's design choice
            // is "kawa runs everywhere, mode is decided by hardware, the
            // client decides whether to accept it."
            warn!(
                "kawa: starting in MOCK attestation mode — {TSM_REPORT_BASE} \
                 unusable: {e}. Every served handshake will carry \
                 platform=\"mock\" and every message on every mock connection \
                 will emit a per-request WARN. Konnect clients with default \
                 acceptMock=false will reject this kawa. Use this mode only \
                 for protocol e2e on non-TEE hardware."
            );
            TeeMode::Mock
        }
    }
}

fn mock_payload(nonce: String) -> AttestationPayload {
    AttestationPayload {
        platform: "mock".into(),
        quote: None,
        cert_chain: None,
        nonce,
        manifest: None,
        manifest_bundle: None,
        gpu_evidence: None,
    }
}

/// Generate a TEE attestation payload. The mode was decided at process
/// start by [`detect_tee_mode`] — this function consults it.
///
/// Real mode talks to configfs-tsm and returns a signed quote. Mock mode
/// returns a deterministic placeholder marked `platform = "mock"` and emits
/// a WARN every call (the caller — handshake path — is once per connection,
/// so this fires per-handshake; per-message warns live in the transport
/// loop, see `server.rs`).
pub async fn generate_attestation(
    server_static_key: &[u8],
    mode: TeeMode,
) -> Result<AttestationPayload, TeeError> {
    let nonce = compute_nonce(server_static_key);

    if mode == TeeMode::Mock {
        warn!(
            "kawa: serving MOCK attestation (platform=\"mock\") — caller will see no signed \
             quote, no cert chain, no real measurements. Production validators reject this."
        );
        return Ok(mock_payload(nonce));
    }

    // Real mode: cached payload covers both constant report_data + constant RTMRs.
    if let Some(cached) = ATTESTATION_CACHE.get() {
        info!("using cached attestation");
        return Ok(cached.clone());
    }

    // Create unique report entry — concurrent connections each get their own.
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let rand_suffix: u32 = rand::random::<u32>() & 0xFFFFFF;
    let entry_name = format!("kawa_{ts}_{rand_suffix:06x}");
    let entry_path = format!("{TSM_REPORT_BASE}/{entry_name}");

    debug!(entry = %entry_path, "creating tsm report entry");
    tokio::fs::create_dir(&entry_path)
        .await
        .map_err(|e| TeeError::Io("create report entry", e))?;

    let result = do_attestation(&entry_path, &nonce).await;

    if let Err(e) = tokio::fs::remove_dir_all(&entry_path).await {
        warn!(entry = %entry_path, error = %e, "failed to clean up tsm report entry");
    }

    if let Ok(ref payload) = result {
        let _ = ATTESTATION_CACHE.set(payload.clone());
        info!("attestation cached for subsequent connections");
    }

    result
}

async fn do_attestation(entry_path: &str, nonce: &str) -> Result<AttestationPayload, TeeError> {
    // Build 64-byte report_data: first 32 bytes = nonce hex parsed to bytes, rest zeros
    let mut report_data = [0u8; 64];
    if nonce.len() != 64 {
        return Err(TeeError::BadNonce);
    }
    for i in 0..32 {
        let hex_byte = &nonce[i * 2..i * 2 + 2];
        report_data[i] = u8::from_str_radix(hex_byte, 16).map_err(|_| TeeError::BadNonce)?;
    }

    // Write report data
    tokio::fs::write(format!("{entry_path}/inblob"), &report_data)
        .await
        .map_err(|e| TeeError::Io("write inblob", e))?;

    // Read generation before
    let gen_before = read_generation(entry_path).await;

    // Detect platform
    let provider = tokio::fs::read_to_string(format!("{entry_path}/provider"))
        .await
        .map_err(|e| TeeError::Io("read provider", e))?;
    let provider_trimmed = provider.trim();
    let platform = if provider_trimmed.contains("sev") || provider_trimmed.contains("snp") {
        "SEV-SNP"
    } else {
        "TDX"
    };
    info!(
        platform,
        provider = provider_trimmed,
        "detected TEE platform"
    );

    // Read quote
    let quote = tokio::fs::read(format!("{entry_path}/outblob"))
        .await
        .map_err(|e| TeeError::Io("read outblob", e))?;
    if quote.is_empty() {
        return Err(TeeError::EmptyQuote);
    }

    // Read certificate chain (optional)
    let cert_chain = match tokio::fs::read(format!("{entry_path}/auxblob")).await {
        Ok(data) if !data.is_empty() => Some(String::from_utf8_lossy(&data).into_owned()),
        _ => {
            // auxblob empty — try fetching certs from teehost over vsock
            // (SNP only: QEMU's sev-snp-certs/auxblob isn't upstream yet)
            if platform == "SEV-SNP" {
                info!("auxblob empty, trying teehost vsock cert fallback");
                match super::vsock_teehost::fetch_snp_certs().await {
                    Ok(certs) => Some(certs),
                    Err(e) => {
                        warn!("teehost cert fallback failed: {e}");
                        None
                    }
                }
            } else {
                None
            }
        }
    };

    // Verify generation didn't change (concurrent modification detection)
    let gen_after = read_generation(entry_path).await;
    if let (Some(before), Some(after)) = (gen_before, gen_after) {
        if before != after {
            return Err(TeeError::ConcurrentModification);
        }
    }

    // Collect GPU CC attestation evidence (best-effort — empty if no CC GPUs)
    let nonce_bytes: [u8; 32] = report_data[..32]
        .try_into()
        .expect("report_data is 64 bytes, slice of 32 always fits");
    let gpu_ev = super::gpu_attest::collect_all_gpu_evidence(&nonce_bytes);
    let gpu_evidence = if gpu_ev.is_empty() {
        None
    } else {
        Some(gpu_ev)
    };

    Ok(AttestationPayload {
        platform: platform.into(),
        quote: Some(BASE64.encode(&quote)),
        cert_chain,
        nonce: nonce.to_string(),
        manifest: None,
        manifest_bundle: None,
        gpu_evidence,
    })
}

async fn read_generation(entry_path: &str) -> Option<String> {
    tokio::fs::read_to_string(format!("{entry_path}/generation"))
        .await
        .ok()
        .map(|s| s.trim().to_string())
}

/// Compute attestation nonce: hex-encoded SHA-256 of the server's static public key.
fn compute_nonce(server_static_key: &[u8]) -> String {
    let hash = Sha256::digest(server_static_key);
    hex::encode(hash)
}

#[derive(Debug, thiserror::Error)]
pub enum TeeError {
    #[error("{0}: {1}")]
    Io(&'static str, std::io::Error),
    #[error("bad nonce hex")]
    BadNonce,
    #[error("empty quote returned from configfs-tsm")]
    EmptyQuote,
    #[error("configfs-tsm generation changed during read — concurrent modification")]
    ConcurrentModification,
}
