import { expect, test } from "bun:test";
import * as Envelope from "@core/transport/envelope.ts";
import { EnvelopeError } from "@core/transport/envelope.ts";

function build(data: Uint8Array, meta?: Uint8Array): Uint8Array {
  // Helper that mirrors kawa's `wrap_frame`: [u32 LE data_len][data][meta].
  const metaBytes = meta ?? new Uint8Array(0);
  const out = new Uint8Array(4 + data.length + metaBytes.length);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, data.length, true);
  out.set(data, 4);
  out.set(metaBytes, 4 + data.length);
  return out;
}

test("envelope: unwraps data + ignores meta", () => {
  const data = new TextEncoder().encode("noise handshake bytes");
  const meta = new TextEncoder().encode('{"object":"kawiri.chunk","req_id":1}');
  const frame = build(data, meta);

  const out = Envelope.unwrap(frame);
  expect(new TextDecoder().decode(out)).toEqual("noise handshake bytes");
});

test("envelope: pure-meta frame unwraps to empty", () => {
  // End-of-stream usage envelope from kawa: data_len = 0, meta carries
  // the {"object":"kawiri.usage",...} JSON. Konnect must not feed empty
  // bytes into Noise — caller treats empty as "skip."
  const meta = new TextEncoder().encode('{"object":"kawiri.usage","req_id":1}');
  const frame = build(new Uint8Array(0), meta);
  expect(Envelope.unwrap(frame).length).toEqual(0);
});

test("envelope: empty data, empty meta", () => {
  // Just a 4-byte zero prefix. Degenerate but legal.
  const frame = new Uint8Array([0, 0, 0, 0]);
  expect(Envelope.unwrap(frame).length).toEqual(0);
});

test("envelope: rejects frame shorter than header", () => {
  expect(() => Envelope.unwrap(new Uint8Array([1, 2, 3]))).toThrow(EnvelopeError);
});

test("envelope: rejects data_len that overflows frame", () => {
  // header claims 100 bytes of data but the frame only carries 8 more.
  const frame = new Uint8Array(12);
  new DataView(frame.buffer).setUint32(0, 100, true);
  expect(() => Envelope.unwrap(frame)).toThrow(EnvelopeError);
});

test("envelope: u32 LE byte order", () => {
  // data_len = 1, so byte 0 = 0x01 and bytes 1..4 = 0. If we ever
  // accidentally switch to BE this test catches it.
  const frame = new Uint8Array([0x01, 0x00, 0x00, 0x00, 0xaa]);
  const out = Envelope.unwrap(frame);
  expect(out.length).toEqual(1);
  expect(out[0]).toEqual(0xaa);
});

test("envelope: looks like talking to pre-envelope kawa (random first 4 bytes)", () => {
  // A raw Noise XX msg1 has random bytes up front. Treating them as
  // u32 LE almost certainly yields a data_len that overflows the
  // frame, which is what we want — the unwrap throws, the client
  // tears the connection down, the user gets a clear error rather
  // than silently mis-decoding Noise.
  const noise = new Uint8Array(96);
  for (let i = 0; i < noise.length; i++) noise[i] = (i * 31 + 7) & 0xff;
  // First 4 bytes interpreted LE: 0x80513207 ≈ 2.15e9, way > 96.
  expect(() => Envelope.unwrap(noise)).toThrow(EnvelopeError);
});

test("envelope: subarray is a view, not a copy", () => {
  // Documenting that unwrap returns a view into the source frame.
  // This matters because callers MAY hold the buffer; if we ever
  // start copying, that perf assumption needs to change.
  const data = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
  const frame = build(data);
  const out = Envelope.unwrap(frame);
  // Mutating the source observably changes the view.
  frame[4] = 0x00;
  expect(out[0]).toEqual(0x00);
});
