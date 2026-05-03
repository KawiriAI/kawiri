import type { AttestationPayload } from "../transport/types.ts";

/** Outcome of validating an attestation payload during the handshake. */
export interface ValidationResult {
  /** Whether the connection should proceed. */
  valid: boolean;
  /**
   * What the *server* claimed about its TEE backing. `"real"` means a
   * hardware-backed quote; `"mock"` means the server is running on
   * non-TEE hardware (or with `MOCK_TEE` forced). The client uses this
   * to decide whether to emit per-message warnings.
   *
   * The mode is only trustworthy if `valid === true` — i.e., the
   * validator ran its checks AND chose to accept this mode.
   */
  mode: "real" | "mock";
}

export interface AttestationValidator {
  validate(payload: AttestationPayload, serverStaticKey: Uint8Array): Promise<ValidationResult>;
}

/** Default: accept all attestations (for development/testing only). */
export class StubValidator implements AttestationValidator {
  async validate(payload: AttestationPayload, _key: Uint8Array): Promise<ValidationResult> {
    return {
      valid: true,
      mode: payload.platform === "mock" ? "mock" : "real",
    };
  }
}
