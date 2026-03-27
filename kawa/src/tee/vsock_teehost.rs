//! vsock client for teehost — ping/pong connectivity check + SNP cert fallback.
//!
//! On boot, the guest pings teehost over vsock to verify the host service is
//! running. For SNP, if configfs-tsm's auxblob is empty (no upstream QEMU
//! sev-snp-certs support), we fetch the VCEK cert chain from teehost instead.
//!
//! Requires: `-device vhost-vsock-pci,guest-cid=3` in QEMU args.

use std::sync::OnceLock;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_vsock::{VsockAddr, VsockStream};
use tracing::info;

/// Cached SNP cert chain — static for the lifetime of the VM (same chip, same TCB).
static SNP_CERTS_CACHE: OnceLock<String> = OnceLock::new();

/// vsock CID 2 = host
const HOST_CID: u32 = 2;
/// teehost listens on port 4050 (matching Intel QGS)
const TEEHOST_PORT: u32 = 4050;

// teehost wire protocol constants (must match teehost/src/proto.rs)
const MAJOR_VERSION: u16 = 1;
const MINOR_VERSION: u16 = 1;
const HEADER_SIZE: usize = 16;
const PING_REQ: u32 = 130;
const PING_RESP: u32 = 131;
const GET_SNP_CERTS_REQ: u32 = 128;
const GET_SNP_CERTS_RESP: u32 = 129;

const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Ping teehost over vsock. Returns the response body (version/status string)
/// or an error if teehost is not reachable.
pub async fn ping_teehost() -> Result<String, TeehostError> {
    let resp = roundtrip(PING_REQ, &[]).await?;
    let body = parse_response_body(&resp, PING_RESP)?;
    let status = String::from_utf8_lossy(body).into_owned();
    Ok(status)
}

/// Fetch SNP VCEK cert chain from teehost over vsock.
///
/// Called as fallback when configfs-tsm auxblob is empty.
/// Returns PEM-encoded cert chain (VCEK + ASK + ARK).
pub async fn fetch_snp_certs() -> Result<String, TeehostError> {
    if let Some(cached) = SNP_CERTS_CACHE.get() {
        info!("using cached SNP certs: {} bytes", cached.len());
        return Ok(cached.clone());
    }

    let resp = roundtrip(GET_SNP_CERTS_REQ, &[]).await?;
    let body = parse_response_body(&resp, GET_SNP_CERTS_RESP)?;
    let certs = String::from_utf8_lossy(body).into_owned();
    info!("fetched SNP certs from teehost: {} bytes", certs.len());

    // Cache for subsequent handshakes — certs are static per chip/TCB
    let _ = SNP_CERTS_CACHE.set(certs.clone());
    Ok(certs)
}

// ── Wire protocol ──

fn build_header(msg_type: u32, total_size: u32) -> [u8; HEADER_SIZE] {
    let mut buf = [0u8; HEADER_SIZE];
    buf[0..2].copy_from_slice(&MAJOR_VERSION.to_le_bytes());
    buf[2..4].copy_from_slice(&MINOR_VERSION.to_le_bytes());
    buf[4..8].copy_from_slice(&msg_type.to_le_bytes());
    buf[8..12].copy_from_slice(&total_size.to_le_bytes());
    // error_code = 0 (already zeroed)
    buf
}

/// Build a framed request: [4-byte BE length][header][body]
fn build_framed_request(msg_type: u32, body: &[u8]) -> Vec<u8> {
    let payload_size = (HEADER_SIZE + body.len()) as u32;
    let header = build_header(msg_type, payload_size);

    let mut msg = Vec::with_capacity(4 + HEADER_SIZE + body.len());
    msg.extend_from_slice(&payload_size.to_be_bytes()); // frame length
    msg.extend_from_slice(&header);
    msg.extend_from_slice(body);
    msg
}

/// Parse response payload, verify msg_type and error_code.
fn parse_response_body(data: &[u8], expected_type: u32) -> Result<&[u8], TeehostError> {
    if data.len() < HEADER_SIZE {
        return Err(TeehostError::Protocol("response too short"));
    }

    let msg_type = u32::from_le_bytes(
        data[4..8]
            .try_into()
            .expect("header bounds already checked"),
    );
    let error_code = u32::from_le_bytes(
        data[12..16]
            .try_into()
            .expect("header bounds already checked"),
    );

    if error_code != 0 {
        return Err(TeehostError::Remote(error_code));
    }
    if msg_type != expected_type {
        return Err(TeehostError::Protocol("unexpected response type"));
    }

    Ok(&data[HEADER_SIZE..])
}

/// Send a framed message to teehost over vsock, read the framed response.
async fn roundtrip(msg_type: u32, body: &[u8]) -> Result<Vec<u8>, TeehostError> {
    let request = build_framed_request(msg_type, body);

    // Connect
    let mut stream = tokio::time::timeout(
        CONNECT_TIMEOUT,
        VsockStream::connect(VsockAddr::new(HOST_CID, TEEHOST_PORT)),
    )
    .await
    .map_err(|_| TeehostError::Timeout)?
    .map_err(TeehostError::Io)?;

    // Send
    stream.write_all(&request).await.map_err(TeehostError::Io)?;
    stream.flush().await.map_err(TeehostError::Io)?;

    // Read response frame: [4-byte BE length][payload]
    let mut len_buf = [0u8; 4];
    tokio::time::timeout(READ_TIMEOUT, stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| TeehostError::Timeout)?
        .map_err(TeehostError::Io)?;

    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 64 * 1024 {
        return Err(TeehostError::Protocol("response too large"));
    }

    let mut payload = vec![0u8; len];
    tokio::time::timeout(READ_TIMEOUT, stream.read_exact(&mut payload))
        .await
        .map_err(|_| TeehostError::Timeout)?
        .map_err(TeehostError::Io)?;

    Ok(payload)
}

#[derive(Debug, thiserror::Error)]
pub enum TeehostError {
    #[error("vsock I/O: {0}")]
    Io(std::io::Error),
    #[error("teehost connection timed out")]
    Timeout,
    #[error("protocol error: {0}")]
    Protocol(&'static str),
    #[error("teehost returned error code {0:#x}")]
    Remote(u32),
}
