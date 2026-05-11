/**
 * kawa wire envelope (server→client direction only).
 *
 * Every binary WebSocket frame kawa sends has this shape:
 *
 *     [u32 LE: data_len] [data: data_len bytes] [meta: remaining bytes]
 *
 * - `data` is what konnect feeds into the Noise machinery (handshake
 *   messages during the XX exchange, ciphertext frames in transport
 *   mode). After unwrap, it's exactly what older pre-envelope kawa
 *   would have sent.
 * - `meta` is router-readable cleartext JSON used for billing and
 *   quota. konnect is NOT a router — it ignores the meta and the
 *   pure-meta end-of-stream frame.
 *
 * The client→server direction stays raw Noise: konnect never wraps
 * outgoing frames.
 *
 * Pure-meta frames (`data_len == 0`) are valid — they're how kawa
 * delivers the end-of-stream usage envelope. Callers should treat
 * an empty unwrap result as "nothing to feed Noise; carry on."
 */

/** Thrown when an inbound frame cannot be parsed as a wire envelope. */
export class EnvelopeError extends Error {}

/**
 * Strip the envelope and return the Noise payload (possibly empty).
 *
 * Throws [`EnvelopeError`] when the frame is shorter than the 4-byte
 * header or its declared `data_len` overflows the frame buffer. Both
 * cases indicate a protocol-level mismatch (e.g. talking to a
 * pre-envelope kawa, or a corrupted relay); the connection should be
 * torn down rather than silently miscoding the Noise stream.
 */
export function unwrap(frame: Uint8Array): Uint8Array {
  if (frame.length < 4) {
    throw new EnvelopeError(`frame shorter than 4-byte envelope header (got ${frame.length})`);
  }
  const dv = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
  const dataLen = dv.getUint32(0, true);
  if (4 + dataLen > frame.length) {
    throw new EnvelopeError(`envelope data_len ${dataLen} overflows frame size ${frame.length}`);
  }
  return frame.subarray(4, 4 + dataLen);
}
