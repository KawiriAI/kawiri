use hkdf::Hkdf;
use sha2::Sha256;

use super::transport::TransportError;

const PQ_SALT: &[u8] = b"pq-upgrade-v1";
const PQ_INFO: &[u8] = b"transport";

/// Generate an XWing keypair. Returns (decapsulation_key_bytes, encapsulation_key_bytes).
pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
    use x_wing::{
        kem::{Kem, KeyExport},
        XWingKem,
    };
    let (dk, ek) = XWingKem::generate_keypair();
    (dk.as_bytes().to_vec(), ek.to_bytes().to_vec())
}

/// Decapsulate a ciphertext using a decapsulation key.
/// Returns the shared secret bytes.
pub fn decapsulate(dk_bytes: &[u8], ct_bytes: &[u8]) -> Result<Vec<u8>, XWingError> {
    use kem::Decapsulate;
    use x_wing::{DecapsulationKey, CIPHERTEXT_SIZE, DECAPSULATION_KEY_SIZE};

    let dk_array: [u8; DECAPSULATION_KEY_SIZE] = dk_bytes
        .try_into()
        .map_err(|_| XWingError::Decapsulate("invalid decapsulation key".into()))?;
    let dk = DecapsulationKey::from(dk_array);

    if ct_bytes.len() != CIPHERTEXT_SIZE {
        return Err(XWingError::Decapsulate("invalid ciphertext".into()));
    }
    let mut ct = x_wing::Ciphertext::default();
    ct.copy_from_slice(ct_bytes);

    // decapsulate is infallible in x-wing
    let ss = dk.decapsulate(&ct);
    Ok(ss.to_vec())
}

/// Derive two 32-byte keys from the XWing shared secret.
///
/// HKDF-SHA256 with salt="pq-upgrade-v1", info="transport".
/// Output: 64 bytes split into key1 (0..32) and key2 (32..64).
/// - Initiator: sends with key1, receives with key2
/// - Responder: sends with key2, receives with key1
pub fn derive_keys(
    kem_secret: &[u8],
    is_initiator: bool,
) -> Result<([u8; 32], [u8; 32]), XWingError> {
    let hk = Hkdf::<Sha256>::new(Some(PQ_SALT), kem_secret);
    let mut okm = [0u8; 64];
    hk.expand(PQ_INFO, &mut okm).map_err(|_| XWingError::Hkdf)?;

    let mut key1 = [0u8; 32];
    let mut key2 = [0u8; 32];
    key1.copy_from_slice(&okm[..32]);
    key2.copy_from_slice(&okm[32..]);

    if is_initiator {
        Ok((key1, key2)) // send=key1, recv=key2
    } else {
        Ok((key2, key1)) // send=key2, recv=key1
    }
}

#[derive(Debug, thiserror::Error)]
pub enum XWingError {
    #[error("decapsulation: {0}")]
    Decapsulate(String),
    #[error("HKDF expansion failed")]
    Hkdf,
    #[error("unexpected message type: {0}")]
    #[allow(dead_code)]
    UnexpectedMessage(String),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("transport: {0}")]
    Transport(#[from] TransportError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_derive_keys_responder() {
        let secret = [0xABu8; 32];
        let (send_key, recv_key) = derive_keys(&secret, false).unwrap();
        let (init_send, init_recv) = derive_keys(&secret, true).unwrap();
        assert_eq!(send_key, init_recv);
        assert_eq!(recv_key, init_send);
    }

    #[test]
    fn hkdf_output_is_deterministic() {
        let secret = b"test-shared-secret-for-xwing-pq!";
        let (k1, k2) = derive_keys(secret, false).unwrap();
        let (k1b, k2b) = derive_keys(secret, false).unwrap();
        assert_eq!(k1, k1b);
        assert_eq!(k2, k2b);
    }

    #[test]
    fn xwing_keygen_and_decapsulate() {
        use x_wing::{kem::Encapsulate, EncapsulationKey};

        let (dk_bytes, ek_bytes) = generate_keypair();

        // Client side: encapsulate
        let ek = EncapsulationKey::try_from(ek_bytes.as_slice()).unwrap();
        let (ct, client_ss) = ek.encapsulate();

        // Server side: decapsulate
        let server_ss = decapsulate(&dk_bytes, &ct).unwrap();

        let client_ss_bytes: &[u8] = client_ss.as_ref();
        assert_eq!(server_ss.as_slice(), client_ss_bytes);
    }
}
