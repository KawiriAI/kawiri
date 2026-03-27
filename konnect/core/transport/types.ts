/** Client → Server */
export interface KawiriRequest {
  id: number;
  method: "GET" | "POST";
  path: string;
  body?: unknown; // JSON-serializable
}

/** Server → Client (non-streaming) */
export interface KawiriResponse {
  id: number;
  status: number;
  body?: unknown;
}

/** Server → Client (streaming chunk) */
export interface KawiriStreamChunk {
  id: number;
  event: "data" | "done" | "error";
  data?: unknown;
}

/** Chat message format */
export interface ChatMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

/** Structured result from a chat completion */
export interface ChatResult {
  content: string;
  usage?: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
  model?: string;
  finish_reason?: string;
}

/** Optional params forwarded to the OpenAI-compatible API */
export interface ChatOptions {
  max_tokens?: number;
  temperature?: number;
  top_p?: number;
  chat_template_kwargs?: Record<string, unknown>;
  [key: string]: unknown;
}

/** Attestation payload sent in Noise handshake msg 1 */
export interface AttestationPayload {
  platform: "TDX" | "SEV-SNP" | "mock";
  quote?: string; // base64-encoded raw quote (for kattmax)
  certChain?: string; // PEM cert chain
  nonce: string; // hex SHA-256 of server's static public key
  manifest?: string; // JSON manifest
  manifestBundle?: string; // Sigstore bundle JSON
}
