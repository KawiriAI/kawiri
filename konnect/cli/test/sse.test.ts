import { describe, expect, test } from "bun:test";
import { renderSse } from "../serve.ts";

function tokenStreamFrom(tokens: string[], throwAt?: number): ReadableStream<string> {
	let i = 0;
	return new ReadableStream<string>({
		pull(c) {
			if (throwAt != null && i === throwAt) {
				c.error(new Error("upstream went away"));
				return;
			}
			if (i >= tokens.length) {
				c.close();
				return;
			}
			c.enqueue(tokens[i]!);
			i++;
		},
	});
}

async function collectSse(stream: ReadableStream<Uint8Array>): Promise<string> {
	const reader = stream.getReader();
	const decoder = new TextDecoder();
	let out = "";
	while (true) {
		const { value, done } = await reader.read();
		if (done) break;
		out += decoder.decode(value, { stream: true });
	}
	out += decoder.decode();
	return out;
}

/** Parse `data: {...}\n\n` chunks back into their JSON objects.
 *  The terminal `[DONE]` is returned as the string sentinel. */
function parseSseEvents(sse: string): (Record<string, unknown> | "[DONE]")[] {
	const events: (Record<string, unknown> | "[DONE]")[] = [];
	for (const line of sse.split("\n")) {
		if (!line.startsWith("data: ")) continue;
		const body = line.slice("data: ".length);
		if (body === "[DONE]") {
			events.push("[DONE]");
			continue;
		}
		events.push(JSON.parse(body));
	}
	return events;
}

describe("renderSse", () => {
	test("emits role chunk → content chunks → finish chunk → [DONE]", async () => {
		const tokens = tokenStreamFrom(["Hello", " ", "world"]);
		const sse = await collectSse(renderSse(tokens, "chatcmpl-x", 1700000000, "qwen3-0.6b"));
		const events = parseSseEvents(sse);

		// 1 role + 3 content + 1 finish + 1 [DONE] = 6 events
		expect(events.length).toBe(6);
		expect(events[0]).toMatchObject({
			object: "chat.completion.chunk",
			id: "chatcmpl-x",
			model: "qwen3-0.6b",
			choices: [{ index: 0, delta: { role: "assistant" }, finish_reason: null }],
		});
		expect(events[1]).toMatchObject({
			choices: [{ index: 0, delta: { content: "Hello" }, finish_reason: null }],
		});
		expect(events[2]).toMatchObject({
			choices: [{ index: 0, delta: { content: " " }, finish_reason: null }],
		});
		expect(events[3]).toMatchObject({
			choices: [{ index: 0, delta: { content: "world" }, finish_reason: null }],
		});
		expect(events[4]).toMatchObject({
			choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
		});
		expect(events[5]).toBe("[DONE]");
		// And [DONE] sentinel after.
		expect(sse.endsWith("data: [DONE]\n\n")).toBe(true);
	});

	test("empty token stream still emits role + finish + [DONE]", async () => {
		const tokens = tokenStreamFrom([]);
		const sse = await collectSse(renderSse(tokens, "x", 0, "m"));
		const events = parseSseEvents(sse);
		expect(events.length).toBe(3);
		expect(events[0]).toMatchObject({ choices: [{ delta: { role: "assistant" } }] });
		expect(events[1]).toMatchObject({ choices: [{ finish_reason: "stop" }] });
		expect(events[2]).toBe("[DONE]");
	});

	test("upstream error surfaces in-band and still terminates with [DONE]", async () => {
		const tokens = tokenStreamFrom(["one", "two"], 1); // error after first token
		const sse = await collectSse(renderSse(tokens, "x", 0, "m"));
		const events = parseSseEvents(sse);
		// role chunk + first token + error chunk + [DONE]
		expect(events.length).toBeGreaterThanOrEqual(4);
		const errorEvent = events.find(
			(e) =>
				typeof e === "object" &&
				e !== null &&
				(e as { choices?: { finish_reason?: string }[] }).choices?.[0]?.finish_reason === "error",
		);
		expect(errorEvent).toBeDefined();
		expect(events[events.length - 1]).toBe("[DONE]");
	});

	test("each chunk is a valid SSE event (data: <json>\\n\\n)", async () => {
		const tokens = tokenStreamFrom(["a", "b"]);
		const sse = await collectSse(renderSse(tokens, "x", 0, "m"));
		// Every `data: ` line is followed by a blank line (the \n\n
		// separator that browsers + node-fetch require to flush an event).
		const blocks = sse.split("\n\n").filter((b) => b.length > 0);
		for (const b of blocks) {
			expect(b.startsWith("data: ")).toBe(true);
		}
	});

	test("onToken fires once per content chunk; onClose fires exactly once at stream end", async () => {
		const tokens = tokenStreamFrom(["a", "b", "c"]);
		let tokenCalls = 0;
		let closeCalls = 0;
		await collectSse(
			renderSse(
				tokens,
				"x",
				0,
				"m",
				() => {
					closeCalls++;
				},
				() => {
					tokenCalls++;
				},
			),
		);
		expect(tokenCalls).toBe(3); // one per content token
		expect(closeCalls).toBe(1); // once, at end
	});

	test("onClose fires exactly once even on error mid-stream", async () => {
		const tokens = tokenStreamFrom(["one"], 1);
		let closeCalls = 0;
		await collectSse(
			renderSse(
				tokens,
				"x",
				0,
				"m",
				() => {
					closeCalls++;
				},
			),
		);
		expect(closeCalls).toBe(1);
	});
});
