import type { AttestationPayload } from "../transport/types.ts";

export interface AttestationValidator {
  validate(payload: AttestationPayload, serverStaticKey: Uint8Array): Promise<boolean>;
}

/** Default: accept all attestations (for development/testing only) */
export class StubValidator implements AttestationValidator {
  async validate(_payload: AttestationPayload, _key: Uint8Array): Promise<boolean> {
    return true;
  }
}
