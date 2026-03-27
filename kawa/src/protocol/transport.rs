use super::cipher_state::{CipherError, CipherState};

/// Transport-agnostic encrypted channel.
///
/// Two implementations:
/// - `SnowTransport`: wraps snow's TransportState (used between handshake and XWing upgrade)
/// - `AesGcmTransport`: own AES-GCM state with nonce=0 (used after XWing key replacement)
pub trait EncryptedTransport: Send {
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, TransportError>;
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, TransportError>;
}

/// Snow-backed transport for the window between Noise handshake completion and XWing upgrade.
pub struct SnowTransport {
    inner: snow::TransportState,
    buf: Vec<u8>,
}

impl SnowTransport {
    pub fn new(transport: snow::TransportState) -> Self {
        Self {
            inner: transport,
            buf: vec![0u8; 65535],
        }
    }

    /// Consume self and return the inner snow::TransportState
    /// (needed for rekey_manually before switching to AesGcmTransport).
    #[allow(dead_code)] // public API for manual rekey
    pub fn into_inner(self) -> snow::TransportState {
        self.inner
    }
}

impl EncryptedTransport for SnowTransport {
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, TransportError> {
        let len = self
            .inner
            .write_message(plaintext, &mut self.buf)
            .map_err(|e| TransportError::Snow(e.to_string()))?;
        Ok(self.buf[..len].to_vec())
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, TransportError> {
        let len = self
            .inner
            .read_message(ciphertext, &mut self.buf)
            .map_err(|e| TransportError::Snow(e.to_string()))?;
        Ok(self.buf[..len].to_vec())
    }
}

/// AES-GCM transport with explicit nonce management.
/// Used after XWing key replacement where nonces reset to 0.
pub struct AesGcmTransport {
    send_cipher: CipherState,
    recv_cipher: CipherState,
}

impl AesGcmTransport {
    /// Create from two 32-byte keys with nonces starting at 0.
    /// `send_key`: encrypts server→client.
    /// `recv_key`: decrypts client→server.
    pub fn new(send_key: &[u8; 32], recv_key: &[u8; 32]) -> Self {
        Self {
            send_cipher: CipherState::new(send_key),
            recv_cipher: CipherState::new(recv_key),
        }
    }
}

impl EncryptedTransport for AesGcmTransport {
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, TransportError> {
        self.send_cipher
            .encrypt(plaintext)
            .map_err(TransportError::Cipher)
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, TransportError> {
        self.recv_cipher
            .decrypt(ciphertext)
            .map_err(TransportError::Cipher)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("snow: {0}")]
    Snow(String),
    #[error("cipher: {0}")]
    Cipher(#[from] CipherError),
}
