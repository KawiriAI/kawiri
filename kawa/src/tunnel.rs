//! Tunnel-mode bidirectional byte relay.
//!
//! Runs after a successful `tunnel.open` handshake on a Noise + X-Wing
//! transport. Bytes flow opaquely between the encrypted WebSocket and a
//! loopback TCP socket inside the CVM. Each side polled concurrently via
//! `tokio::select!` — one task, no shared state, clean borrows of the
//! single `EncryptedTransport`.
//!
//! Backpressure: TCP's own kernel-buffer + WebSocket's send-side buffering
//! provide end-to-end flow control. We additionally cap each frame at
//! `TUNNEL_FRAME_SIZE` so a single decrypted plaintext is always one byte
//! chunk (no chunked-frame assembly in tunnel mode).
//!
//! Termination: any of (a) WS close, (b) socket EOF, (c) idle timeout,
//! (d) write error in either direction. We do not implement TCP half-close
//! in v1; SSH itself doesn't depend on it.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use hyper_tungstenite::tungstenite::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use crate::protocol::framer;
use crate::protocol::transport::EncryptedTransport;

/// Max plaintext bytes per encrypted frame. Sized well under the framer's
/// MAX_NOISE_PAYLOAD (~64K) so every tunnel frame fits in a single Noise
/// message and the chunked-frame path is never exercised.
pub const TUNNEL_FRAME_SIZE: usize = 32 * 1024;

/// Both directions silent for this long ⇒ kill the tunnel. The select! loop
/// rebuilds this future every iteration, so it's a since-last-traffic timer,
/// not a hard session cap.
pub const TUNNEL_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Run the relay until either end disconnects or the idle timer fires.
/// Returns Ok on graceful close, Err on protocol violation or transport error.
pub async fn relay<S, R>(
    transport: &mut dyn EncryptedTransport,
    ws_sink: &mut S,
    ws_stream: &mut R,
    upstream: TcpStream,
) -> anyhow::Result<()>
where
    S: futures_util::Sink<Message, Error = hyper_tungstenite::tungstenite::Error> + Unpin,
    R: futures_util::Stream<Item = Result<Message, hyper_tungstenite::tungstenite::Error>> + Unpin,
{
    let (mut up_read, mut up_write) = upstream.into_split();
    let mut buf = vec![0u8; TUNNEL_FRAME_SIZE];
    let mut bytes_in: u64 = 0;
    let mut bytes_out: u64 = 0;

    loop {
        tokio::select! {
            biased; // drain inbound WS first so a fast client doesn't starve

            // Client → upstream: decrypt the next WS frame, write bytes to socket.
            ws_msg = ws_stream.next() => {
                match ws_msg {
                    Some(Ok(Message::Binary(data))) => {
                        let plain = transport.decrypt(&data)?;
                        let frame = framer::decode(&plain)?;
                        // Tunnel mode is single-frame only — chunked path is for
                        // RPC's potentially-large JSON. Reject defensively.
                        if frame.flag != 0x00 {
                            return Err(anyhow::anyhow!(
                                "tunnel: chunked frames not allowed (flag={:#x})",
                                frame.flag
                            ));
                        }
                        if frame.payload.is_empty() {
                            // Empty frame = clean shutdown signal from client.
                            debug!("tunnel: client EOF (in={bytes_in} out={bytes_out})");
                            return Ok(());
                        }
                        bytes_in += frame.payload.len() as u64;
                        if let Err(e) = up_write.write_all(&frame.payload).await {
                            debug!("tunnel: upstream write failed: {e}");
                            return Ok(());
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        debug!("tunnel: ws closed (in={bytes_in} out={bytes_out})");
                        return Ok(());
                    }
                    Some(Ok(_)) => {} // pings/pongs/text — ignore
                    Some(Err(e)) => return Err(e.into()),
                }
            }

            // Upstream → client: read socket bytes, encrypt, send WS frame.
            n = up_read.read(&mut buf) => {
                let n = match n {
                    Ok(n) => n,
                    Err(e) => {
                        debug!("tunnel: upstream read failed: {e}");
                        return Ok(());
                    }
                };
                if n == 0 {
                    // Send empty-payload frame as EOF marker, then close.
                    let frames = framer::encode(&[]);
                    for f in frames {
                        let enc = transport.encrypt(&f)?;
                        ws_sink.send(Message::binary(enc)).await?;
                    }
                    debug!("tunnel: upstream EOF (in={bytes_in} out={bytes_out})");
                    return Ok(());
                }
                bytes_out += n as u64;
                let frames = framer::encode(&buf[..n]);
                for f in frames {
                    let enc = transport.encrypt(&f)?;
                    ws_sink.send(Message::binary(enc)).await?;
                }
            }

            _ = tokio::time::sleep(TUNNEL_IDLE_TIMEOUT) => {
                warn!("tunnel: idle timeout (in={bytes_in} out={bytes_out})");
                return Ok(());
            }
        }
    }
}
