use std::collections::HashMap;

/// Max Noise payload before AES-GCM tag overhead.
const MAX_NOISE_PAYLOAD: usize = 65519; // 65535 - 16
/// Chunked frame header: 1 flag + 4 chunk_id + 2 chunk_index + 2 total_chunks.
const FRAME_HEADER_SIZE: usize = 9;
/// Max payload per chunk.
const MAX_CHUNK_PAYLOAD: usize = MAX_NOISE_PAYLOAD - FRAME_HEADER_SIZE; // 65510
/// Limits to prevent resource exhaustion.
const MAX_TOTAL_CHUNKS: usize = 1024;
const MAX_PENDING_MESSAGES: usize = 16;

/// Single-frame flag.
const FLAG_SINGLE: u8 = 0x00;
/// Chunked-frame flag.
const FLAG_CHUNKED: u8 = 0x01;

#[derive(Debug)]
pub struct DecodedFrame {
    pub flag: u8,
    pub payload: Vec<u8>,
    pub chunk_id: u32,
    pub chunk_index: u16,
    pub total_chunks: u16,
}

/// Encode a message into one or more frames.
pub fn encode(data: &[u8]) -> Vec<Vec<u8>> {
    if data.len() <= MAX_NOISE_PAYLOAD {
        // Single frame: [0x00 | payload]
        let mut frame = Vec::with_capacity(1 + data.len());
        frame.push(FLAG_SINGLE);
        frame.extend_from_slice(data);
        return vec![frame];
    }

    // Chunked: split into ceil(len / MAX_CHUNK_PAYLOAD) chunks
    let total_chunks = data.len().div_ceil(MAX_CHUNK_PAYLOAD);
    let chunk_id = rand::random::<u32>();
    let mut frames = Vec::with_capacity(total_chunks);

    for i in 0..total_chunks {
        let start = i * MAX_CHUNK_PAYLOAD;
        let end = std::cmp::min(start + MAX_CHUNK_PAYLOAD, data.len());
        let chunk_data = &data[start..end];

        let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + chunk_data.len());
        frame.push(FLAG_CHUNKED);
        frame.extend_from_slice(&chunk_id.to_be_bytes());
        frame.extend_from_slice(&(i as u16).to_be_bytes());
        frame.extend_from_slice(&(total_chunks as u16).to_be_bytes());
        frame.extend_from_slice(chunk_data);
        frames.push(frame);
    }

    frames
}

/// Decode a single frame from raw bytes.
pub fn decode(raw: &[u8]) -> Result<DecodedFrame, FramerError> {
    if raw.is_empty() {
        return Err(FramerError::EmptyFrame);
    }

    let flag = raw[0];
    match flag {
        FLAG_SINGLE => Ok(DecodedFrame {
            flag,
            payload: raw[1..].to_vec(),
            chunk_id: 0,
            chunk_index: 0,
            total_chunks: 1,
        }),
        FLAG_CHUNKED => {
            if raw.len() < FRAME_HEADER_SIZE {
                return Err(FramerError::TruncatedHeader);
            }
            let chunk_id = u32::from_be_bytes([raw[1], raw[2], raw[3], raw[4]]);
            let chunk_index = u16::from_be_bytes([raw[5], raw[6]]);
            let total_chunks = u16::from_be_bytes([raw[7], raw[8]]);
            Ok(DecodedFrame {
                flag,
                payload: raw[FRAME_HEADER_SIZE..].to_vec(),
                chunk_id,
                chunk_index,
                total_chunks,
            })
        }
        _ => Err(FramerError::UnknownFlag(flag)),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FramerError {
    #[error("empty frame")]
    EmptyFrame,
    #[error("truncated chunk header")]
    TruncatedHeader,
    #[error("unknown frame flag: {0:#x}")]
    UnknownFlag(u8),
    #[error("too many chunks: {0}")]
    TooManyChunks(u16),
    #[error("chunk index {0} >= total {1}")]
    InvalidChunkIndex(u16, u16),
    #[error("too many pending messages")]
    TooManyPending,
}

/// Reassembles chunked frames into complete messages.
pub struct FrameAssembler {
    pending: HashMap<u32, PendingMessage>,
}

struct PendingMessage {
    total: u16,
    received: HashMap<u16, Vec<u8>>,
}

impl FrameAssembler {
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
        }
    }

    /// Process a decoded frame. Returns the complete message if all chunks have arrived.
    pub fn process(&mut self, frame: DecodedFrame) -> Result<Option<Vec<u8>>, FramerError> {
        if frame.flag == FLAG_SINGLE {
            return Ok(Some(frame.payload));
        }

        if frame.total_chunks as usize > MAX_TOTAL_CHUNKS {
            return Err(FramerError::TooManyChunks(frame.total_chunks));
        }
        if frame.chunk_index >= frame.total_chunks {
            return Err(FramerError::InvalidChunkIndex(
                frame.chunk_index,
                frame.total_chunks,
            ));
        }
        if self.pending.len() >= MAX_PENDING_MESSAGES && !self.pending.contains_key(&frame.chunk_id)
        {
            return Err(FramerError::TooManyPending);
        }

        let msg = self
            .pending
            .entry(frame.chunk_id)
            .or_insert(PendingMessage {
                total: frame.total_chunks,
                received: HashMap::new(),
            });
        msg.received.insert(frame.chunk_index, frame.payload);

        if msg.received.len() == msg.total as usize {
            let msg = self.pending.remove(&frame.chunk_id).unwrap();
            let mut complete = Vec::new();
            for i in 0..msg.total {
                if let Some(chunk) = msg.received.get(&i) {
                    complete.extend_from_slice(chunk);
                }
            }
            Ok(Some(complete))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_frame_roundtrip() {
        let data = b"hello world";
        let frames = encode(data);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0][0], FLAG_SINGLE);

        let decoded = decode(&frames[0]).unwrap();
        assert_eq!(decoded.flag, FLAG_SINGLE);
        assert_eq!(decoded.payload, data);
    }

    #[test]
    fn chunked_frame_roundtrip() {
        // Create data larger than MAX_NOISE_PAYLOAD
        let data = vec![0xAB; MAX_NOISE_PAYLOAD + 100];
        let frames = encode(&data);
        assert!(frames.len() > 1);

        let mut assembler = FrameAssembler::new();
        let mut result = None;
        for frame in &frames {
            let decoded = decode(frame).unwrap();
            assert_eq!(decoded.flag, FLAG_CHUNKED);
            if let Some(complete) = assembler.process(decoded).unwrap() {
                result = Some(complete);
            }
        }
        assert_eq!(result.unwrap(), data);
    }

    #[test]
    fn single_frame_boundary() {
        // Exactly MAX_NOISE_PAYLOAD should be a single frame
        let data = vec![0x42; MAX_NOISE_PAYLOAD];
        let frames = encode(&data);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0][0], FLAG_SINGLE);
    }

    #[test]
    fn chunked_at_boundary_plus_one() {
        let data = vec![0x42; MAX_NOISE_PAYLOAD + 1];
        let frames = encode(&data);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0][0], FLAG_CHUNKED);
    }

    #[test]
    fn out_of_order_assembly() {
        // Use exactly 3 chunks worth of data
        let data = vec![0xCD; MAX_CHUNK_PAYLOAD * 3];
        let frames = encode(&data);
        assert_eq!(frames.len(), 3);

        // Feed chunks in reverse order
        let mut assembler = FrameAssembler::new();
        assert!(assembler
            .process(decode(&frames[2]).unwrap())
            .unwrap()
            .is_none());
        assert!(assembler
            .process(decode(&frames[0]).unwrap())
            .unwrap()
            .is_none());
        let result = assembler
            .process(decode(&frames[1]).unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn empty_frame_error() {
        assert!(decode(&[]).is_err());
    }

    #[test]
    fn unknown_flag_error() {
        assert!(decode(&[0xFF, 0x01]).is_err());
    }
}
