use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use tracing::{debug, info, warn};

use crate::protocol::types::AttestationPayload;

const TSM_REPORT_BASE: &str = "/sys/kernel/config/tsm/report";

/// Cached attestation payload — the quote only depends on report_data (derived
/// from the server's static key, constant per process) and RTMRs (constant at
/// runtime). Generating via configfs-tsm takes ~1s due to SEAMCALL/firmware
/// latency, so we cache after the first successful generation.
static ATTESTATION_CACHE: OnceLock<AttestationPayload> = OnceLock::new();

#[cfg(feature = "mock")]
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

/// Generate a TEE attestation payload using configfs-tsm.
///
/// Fails hard if configfs-tsm is not mounted — no ioctl fallback.
pub async fn generate_attestation(
    server_static_key: &[u8],
    mock: bool,
) -> Result<AttestationPayload, TeeError> {
    let nonce = compute_nonce(server_static_key);

    #[cfg(feature = "mock")]
    if mock {
        info!("using mock attestation (MOCK_TEE=true)");
        return Ok(mock_payload(nonce));
    }

    #[cfg(not(feature = "mock"))]
    if mock {
        return Err(TeeError::MockDisabled);
    }

    // Return cached attestation if available — the quote depends only on
    // report_data (static key hash, constant) and RTMRs (constant at runtime).
    if let Some(cached) = ATTESTATION_CACHE.get() {
        info!("using cached attestation");
        return Ok(cached.clone());
    }

    // Auto-detect: if configfs-tsm isn't mounted, no TEE hardware
    if !tokio::fs::try_exists(TSM_REPORT_BASE)
        .await
        .unwrap_or(false)
    {
        #[cfg(feature = "mock")]
        {
            warn!("configfs-tsm not mounted at {TSM_REPORT_BASE} — no TEE hardware, using mock attestation");
            return Ok(mock_payload(nonce));
        }
        #[cfg(not(feature = "mock"))]
        {
            return Err(TeeError::NoTeeHardware);
        }
    }

    // Create unique report entry
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let rand_suffix: u32 = rand::random::<u32>() & 0xFFFFFF;
    let entry_name = format!("kawa_{ts}_{rand_suffix:06x}");
    let entry_path = format!("{TSM_REPORT_BASE}/{entry_name}");

    debug!(entry = %entry_path, "creating tsm report entry");
    match tokio::fs::create_dir(&entry_path).await {
        Ok(()) => {}
        Err(e) => {
            // configfs path exists but no TEE driver registered (e.g. tee=none)
            #[cfg(feature = "mock")]
            {
                warn!(
                    "configfs-tsm create_dir failed ({e}) — no TEE backend, using mock attestation"
                );
                return Ok(mock_payload(nonce));
            }
            #[cfg(not(feature = "mock"))]
            {
                return Err(TeeError::Io("create report entry", e));
            }
        }
    }

    // Ensure cleanup on all paths
    let result = do_attestation(&entry_path, &nonce).await;

    // Cleanup the report entry
    if let Err(e) = tokio::fs::remove_dir_all(&entry_path).await {
        warn!(entry = %entry_path, error = %e, "failed to clean up tsm report entry");
    }

    // Cache on success
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
    #[error("mock attestation disabled — build with --features mock for dev/testing")]
    MockDisabled,
    #[error("no TEE hardware — configfs-tsm not mounted (mock feature not enabled)")]
    NoTeeHardware,
}
