import { expect, test } from "bun:test";
import * as Framer from "@core/transport/framer.ts";
import { FrameAssembler } from "@core/transport/framer.ts";

test("framer: small message single frame", () => {
  const data = new TextEncoder().encode("hello world");
  const frames = Framer.encode(data);
  expect(frames.length).toEqual(1);

  const decoded = Framer.decode(frames[0]);
  expect(decoded.flag).toEqual(0);
  expect(new TextDecoder().decode(decoded.payload)).toEqual("hello world");
});

test("framer: empty payload", () => {
  const data = new Uint8Array(0);
  const frames = Framer.encode(data);
  expect(frames.length).toEqual(1);

  const decoded = Framer.decode(frames[0]);
  expect(decoded.flag).toEqual(0);
  expect(decoded.payload.length).toEqual(0);
});

test("framer: large message chunked", () => {
  // Create a 200KB payload (will require chunking)
  const size = 200_000;
  const data = new Uint8Array(size);
  for (let i = 0; i < size; i++) data[i] = i & 0xff;

  const frames = Framer.encode(data);
  // Should need multiple frames
  expect(frames.length > 1).toEqual(true);

  // All frames should be chunked (flag 0x01)
  for (const frame of frames) {
    expect(frame[0]).toEqual(0x01);
  }

  // Decode and reassemble
  const assembler = new FrameAssembler();
  let result: Uint8Array | null = null;

  for (let i = 0; i < frames.length; i++) {
    const decoded = Framer.decode(frames[i]);
    result = assembler.processFrame(decoded);
    if (i < frames.length - 1) {
      expect(result).toEqual(null); // Not complete yet
    }
  }

  // Should be complete now
  expect(result?.length).toEqual(size);
  expect(result?.[0]).toEqual(0);
  expect(result?.[1]).toEqual(1);
  expect(result?.[size - 1]).toEqual((size - 1) & 0xff);
});

test("framer: assembler handles out-of-order chunks", () => {
  const size = 200_000;
  const data = new Uint8Array(size);
  for (let i = 0; i < size; i++) data[i] = i & 0xff;

  const frames = Framer.encode(data);
  // Reverse the order of chunks
  const reversed = [...frames].reverse();

  const assembler = new FrameAssembler();
  let result: Uint8Array | null = null;

  for (const frame of reversed) {
    const decoded = Framer.decode(frame);
    const r = assembler.processFrame(decoded);
    if (r !== null) result = r;
  }

  expect(result?.length).toEqual(size);
  // Verify byte-for-byte equality
  for (let i = 0; i < size; i++) {
    expect(result?.[i]).toEqual(data[i]);
  }
});

test("framer: single-frame through assembler", () => {
  const data = new TextEncoder().encode('{"hello":"world"}');
  const frames = Framer.encode(data);
  const decoded = Framer.decode(frames[0]);

  const assembler = new FrameAssembler();
  const result = assembler.processFrame(decoded);
  if (!result) throw new Error("expected result");
  expect(new TextDecoder().decode(result)).toEqual('{"hello":"world"}');
});

test("framer: max single frame boundary", () => {
  // Exactly at the boundary — should still be single frame
  const data = new Uint8Array(65519);
  const frames = Framer.encode(data);
  expect(frames.length).toEqual(1);
  expect(frames[0][0]).toEqual(0x00); // single frame flag

  // One byte over — should chunk
  const data2 = new Uint8Array(65520);
  const frames2 = Framer.encode(data2);
  expect(frames2.length > 1).toEqual(true);
  expect(frames2[0][0]).toEqual(0x01); // chunked flag
});
