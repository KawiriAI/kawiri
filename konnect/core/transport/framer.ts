/** Max payload before AES-GCM tag: 65535 - 16 = 65519 */
const MAX_NOISE_PAYLOAD = 65519;
const FRAME_HEADER_SIZE = 9; // 1 flag + 4 chunk_id + 2 chunk_index + 2 total_chunks
const MAX_CHUNK_PAYLOAD = MAX_NOISE_PAYLOAD - FRAME_HEADER_SIZE;
const MAX_TOTAL_CHUNKS = 1024; // Prevents unbounded memory growth
const MAX_PENDING_MESSAGES = 16; // Max concurrent chunked messages

export interface DecodedFrame {
  flag: number;
  chunkId?: number;
  chunkIndex?: number;
  totalChunks?: number;
  payload: Uint8Array;
}

export function encode(data: Uint8Array): Uint8Array[] {
  if (data.length <= MAX_NOISE_PAYLOAD) {
    // Single frame: 0x00 + payload
    const frame = new Uint8Array(1 + data.length);
    frame[0] = 0x00;
    frame.set(data, 1);
    return [frame];
  }

  // Chunked
  const chunkId = crypto.getRandomValues(new Uint8Array(4));
  const totalChunks = Math.ceil(data.length / MAX_CHUNK_PAYLOAD);
  const frames: Uint8Array[] = [];

  for (let i = 0; i < totalChunks; i++) {
    const start = i * MAX_CHUNK_PAYLOAD;
    const end = Math.min(start + MAX_CHUNK_PAYLOAD, data.length);
    const payload = data.slice(start, end);

    const frame = new Uint8Array(FRAME_HEADER_SIZE + payload.length);
    frame[0] = 0x01;
    frame.set(chunkId, 1);
    const dv = new DataView(frame.buffer);
    dv.setUint16(5, i, false);
    dv.setUint16(7, totalChunks, false);
    frame.set(payload, FRAME_HEADER_SIZE);
    frames.push(frame);
  }
  return frames;
}

export function decode(frame: Uint8Array): DecodedFrame {
  if (frame.length < 1) {
    throw new Error("Frame too short");
  }
  const flag = frame[0];
  if (flag === 0x00) {
    return { flag: 0, payload: frame.slice(1) };
  }
  if (frame.length < FRAME_HEADER_SIZE) {
    throw new Error(`Chunked frame too short: ${frame.length} < ${FRAME_HEADER_SIZE}`);
  }
  const dv = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
  return {
    flag: 1,
    chunkId: dv.getUint32(1, false),
    chunkIndex: dv.getUint16(5, false),
    totalChunks: dv.getUint16(7, false),
    payload: frame.slice(FRAME_HEADER_SIZE),
  };
}

/** Collects chunked frames and returns complete message when all chunks arrive. */
export class FrameAssembler {
  private pending = new Map<number, { total: number; received: Map<number, Uint8Array> }>();

  /** Process a decoded frame. Returns complete message if all chunks arrived, else null. */
  processFrame(decoded: DecodedFrame): Uint8Array | null {
    if (decoded.flag === 0) {
      return decoded.payload;
    }

    if (decoded.chunkId == null || decoded.totalChunks == null || decoded.chunkIndex == null) {
      throw new Error("Chunked frame missing chunkId, totalChunks, or chunkIndex");
    }
    const id = decoded.chunkId;
    const total = decoded.totalChunks;
    const index = decoded.chunkIndex;

    // Bounds validation
    if (total > MAX_TOTAL_CHUNKS) {
      throw new Error(`totalChunks ${total} exceeds max ${MAX_TOTAL_CHUNKS}`);
    }
    if (index >= total) {
      throw new Error(`chunkIndex ${index} >= totalChunks ${total}`);
    }

    if (!this.pending.has(id)) {
      if (this.pending.size >= MAX_PENDING_MESSAGES) {
        throw new Error("Too many pending chunked messages");
      }
      this.pending.set(id, { total, received: new Map() });
    }

    const entry = this.pending.get(id);
    if (!entry) throw new Error(`No pending entry for chunkId ${id}`);
    entry.received.set(index, decoded.payload);

    if (entry.received.size === entry.total) {
      // All chunks arrived — reassemble
      let totalLength = 0;
      for (let i = 0; i < entry.total; i++) {
        const chunk = entry.received.get(i);
        if (!chunk) throw new Error(`Missing chunk at index ${i}`);
        totalLength += chunk.length;
      }
      const result = new Uint8Array(totalLength);
      let offset = 0;
      for (let i = 0; i < entry.total; i++) {
        const chunk = entry.received.get(i);
        if (!chunk) throw new Error(`Missing chunk at index ${i}`);
        result.set(chunk, offset);
        offset += chunk.length;
      }
      this.pending.delete(id);
      return result;
    }

    return null;
  }
}
