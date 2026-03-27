use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit};

/// AES-256-GCM cipher state with explicit nonce counter.
///
/// Used after XWing key replacement (where nonces reset to 0).
/// Matches the TypeScript CipherState in kawiri/src/noise/cipher_state.ts.
///
/// Nonce format: 12 bytes = [4 zero bytes | 8 big-endian counter bytes]
pub struct CipherState {
    cipher: Aes256Gcm,
    nonce: u64,
}

impl CipherState {
    /// Create a new cipher state with the given 32-byte key and nonce starting at 0.
    pub fn new(raw_key: &[u8; 32]) -> Self {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(raw_key));
        Self { cipher, nonce: 0 }
    }

    /// Encrypt plaintext with empty additional data. Increments nonce.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
        let iv = self.format_nonce();
        let ct = self
            .cipher
            .encrypt(GenericArray::from_slice(&iv), plaintext)
            .map_err(|_| CipherError::EncryptFailed)?;
        self.nonce = self
            .nonce
            .checked_add(1)
            .ok_or(CipherError::NonceOverflow)?;
        Ok(ct)
    }

    /// Decrypt ciphertext with empty additional data. Increments nonce.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CipherError> {
        let iv = self.format_nonce();
        let pt = self
            .cipher
            .decrypt(GenericArray::from_slice(&iv), ciphertext)
            .map_err(|_| CipherError::DecryptFailed)?;
        self.nonce = self
            .nonce
            .checked_add(1)
            .ok_or(CipherError::NonceOverflow)?;
        Ok(pt)
    }

    /// 12-byte nonce: 4 zero bytes + 8 big-endian counter bytes.
    fn format_nonce(&self) -> [u8; 12] {
        let mut iv = [0u8; 12];
        iv[4..12].copy_from_slice(&self.nonce.to_be_bytes());
        iv
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CipherError {
    #[error("encryption failed")]
    EncryptFailed,
    #[error("decryption failed")]
    DecryptFailed,
    #[error("nonce counter overflow")]
    NonceOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let mut enc = CipherState::new(&key);
        let mut dec = CipherState::new(&key);

        let plaintext = b"hello kawa";
        let ct = enc.encrypt(plaintext).unwrap();
        assert_ne!(ct, plaintext);

        let pt = dec.decrypt(&ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn nonce_increments() {
        let key = [0x01u8; 32];
        let mut enc = CipherState::new(&key);
        let mut dec = CipherState::new(&key);

        // Encrypt two messages — different nonces produce different ciphertexts
        let ct1 = enc.encrypt(b"msg1").unwrap();
        let ct2 = enc.encrypt(b"msg1").unwrap();
        assert_ne!(ct1, ct2);

        // Decrypt in order
        assert_eq!(dec.decrypt(&ct1).unwrap(), b"msg1");
        assert_eq!(dec.decrypt(&ct2).unwrap(), b"msg1");
    }

    #[test]
    fn wrong_key_fails() {
        let mut enc = CipherState::new(&[0x01u8; 32]);
        let mut dec = CipherState::new(&[0x02u8; 32]);

        let ct = enc.encrypt(b"secret").unwrap();
        assert!(dec.decrypt(&ct).is_err());
    }

    #[test]
    fn wrong_nonce_order_fails() {
        let key = [0x01u8; 32];
        let mut enc = CipherState::new(&key);
        let mut dec = CipherState::new(&key);

        let _ct1 = enc.encrypt(b"first").unwrap();
        let ct2 = enc.encrypt(b"second").unwrap();

        // Trying to decrypt ct2 at nonce 0 (skipping ct1) should fail
        assert!(dec.decrypt(&ct2).is_err());
    }

    #[test]
    fn nonce_format_matches_spec() {
        let cs = CipherState {
            cipher: Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&[0u8; 32])),
            nonce: 0x0102030405060708,
        };
        let iv = cs.format_nonce();
        assert_eq!(
            iv,
            [0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
    }
}
