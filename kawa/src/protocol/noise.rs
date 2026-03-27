use snow::{Builder, HandshakeState};

use super::transport::SnowTransport;

const NOISE_PATTERN: &str = "Noise_XX_25519_AESGCM_SHA256";

/// Server's long-lived static keypair.
pub struct StaticKeypair {
    pub keypair: snow::Keypair,
}

impl StaticKeypair {
    pub fn generate() -> Result<Self, NoiseError> {
        let builder = Builder::new(NOISE_PATTERN.parse().map_err(|_| NoiseError::BadPattern)?);
        let keypair = builder.generate_keypair().map_err(NoiseError::Snow)?;
        Ok(Self { keypair })
    }

    pub fn public_key(&self) -> &[u8] {
        &self.keypair.public
    }
}

/// Noise_XX responder for a single connection.
pub struct NoiseResponder {
    hs: HandshakeState,
    buf: Vec<u8>,
}

impl NoiseResponder {
    /// Create a new responder using the server's static keypair.
    pub fn new(static_key: &snow::Keypair) -> Result<Self, NoiseError> {
        let hs = Builder::new(NOISE_PATTERN.parse().map_err(|_| NoiseError::BadPattern)?)
            .local_private_key(&static_key.private)
            .build_responder()
            .map_err(NoiseError::Snow)?;
        Ok(Self {
            hs,
            buf: vec![0u8; 65535],
        })
    }

    /// Read handshake message 0 from client (client's ephemeral key).
    pub fn read_msg0(&mut self, msg: &[u8]) -> Result<(), NoiseError> {
        self.hs
            .read_message(msg, &mut self.buf)
            .map_err(NoiseError::Snow)?;
        Ok(())
    }

    /// Write handshake message 1 with attestation payload.
    /// Returns the encoded message bytes to send to the client.
    pub fn write_msg1(&mut self, attestation_json: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let len = self
            .hs
            .write_message(attestation_json, &mut self.buf)
            .map_err(NoiseError::Snow)?;
        Ok(self.buf[..len].to_vec())
    }

    /// Read handshake message 2 from client (client's static key).
    pub fn read_msg2(&mut self, msg: &[u8]) -> Result<(), NoiseError> {
        self.hs
            .read_message(msg, &mut self.buf)
            .map_err(NoiseError::Snow)?;
        Ok(())
    }

    /// Transition to transport mode after handshake is complete.
    pub fn into_transport(self) -> Result<SnowTransport, NoiseError> {
        let transport = self.hs.into_transport_mode().map_err(NoiseError::Snow)?;
        Ok(SnowTransport::new(transport))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum NoiseError {
    #[error("invalid noise pattern")]
    BadPattern,
    #[error("snow: {0}")]
    Snow(snow::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::transport::EncryptedTransport;

    #[test]
    fn handshake_roundtrip() {
        // Generate server and client keypairs
        let pattern = NOISE_PATTERN.parse().unwrap();
        let server_kp = Builder::new(pattern).generate_keypair().unwrap();
        let pattern = NOISE_PATTERN.parse().unwrap();
        let client_kp = Builder::new(pattern).generate_keypair().unwrap();

        // Server responder
        let mut responder = NoiseResponder::new(&server_kp).unwrap();

        // Client initiator
        let mut client_hs = Builder::new(NOISE_PATTERN.parse().unwrap())
            .local_private_key(&client_kp.private)
            .build_initiator()
            .unwrap();

        let mut buf = vec![0u8; 65535];

        // msg 0: client → server (ephemeral key)
        let len = client_hs.write_message(&[], &mut buf).unwrap();
        let msg0 = buf[..len].to_vec();
        responder.read_msg0(&msg0).unwrap();

        // msg 1: server → client (ephemeral + static + attestation)
        let attestation = b"{\"platform\":\"mock\",\"nonce\":\"abc123\"}";
        let msg1 = responder.write_msg1(attestation).unwrap();
        let len = client_hs.read_message(&msg1, &mut buf).unwrap();
        let payload = &buf[..len];
        assert_eq!(payload, attestation);

        // msg 2: client → server (static key)
        let len = client_hs.write_message(&[], &mut buf).unwrap();
        let msg2 = buf[..len].to_vec();
        responder.read_msg2(&msg2).unwrap();

        // Both transition to transport
        let mut server_transport = responder.into_transport().unwrap();
        let mut client_transport = client_hs.into_transport_mode().unwrap();

        // Server encrypts, client decrypts
        let ct = server_transport.encrypt(b"hello from server").unwrap();
        let len = client_transport.read_message(&ct, &mut buf).unwrap();
        assert_eq!(&buf[..len], b"hello from server");

        // Client encrypts, server decrypts
        let len = client_transport
            .write_message(b"hello from client", &mut buf)
            .unwrap();
        let ct = buf[..len].to_vec();
        let pt = server_transport.decrypt(&ct).unwrap();
        assert_eq!(pt, b"hello from client");
    }
}
