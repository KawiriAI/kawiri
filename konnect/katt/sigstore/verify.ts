import { extractValidity, parseCertificate } from "../der.ts";
import { parseBundle } from "./bundle.ts";
import { verifyDSSESignature } from "./dsse.ts";
import { verifyFulcioCert, verifySCTs } from "./fulcio.ts";
import { verifyTLogEntry } from "./rekor.ts";
import { verifyRFC3161Timestamps } from "./timestamp.ts";
import SIGSTORE_TRUSTED_ROOT from "./trusted-root.ts";
import type { CodeMeasurements, SigstoreVerifyOptions, SigstoreVerifyResult, TrustedRoot } from "./types.ts";
import { SigstoreError } from "./types.ts";

const DEFAULT_TRUSTED_ROOT_URL =
  "https://raw.githubusercontent.com/sigstore/root-signing/main/targets/trusted_root.json";

/**
 * Fetch live Sigstore trusted root from upstream.
 * Requires network access — will not work in browsers (no CORS).
 */
export async function fetchLiveTrustedRoot(trustedRootUrl?: string): Promise<TrustedRoot> {
  const res = await fetch(trustedRootUrl ?? DEFAULT_TRUSTED_ROOT_URL);
  if (!res.ok)
    throw new SigstoreError("CERTIFICATE_ERROR", `Failed to fetch Sigstore trusted root: HTTP ${res.status}`);
  type RawTLog = {
    baseUrl: string;
    hashAlgorithm: string;
    publicKey: { rawBytes: string; keyDetails: string; validFor: { start: string; end?: string } };
    logId: { keyId: string };
  };
  type RawCert = { rawBytes: string };
  type RawCA = {
    subject: { organization: string; commonName: string };
    uri: string;
    certChain: { certificates: RawCert[] };
    validFor: { start: string; end?: string };
  };

  const raw: { tlogs: RawTLog[]; certificateAuthorities: RawCA[]; ctlogs: RawTLog[]; timestampAuthorities: RawCA[] } =
    await res.json();
  return {
    tlogs: raw.tlogs.map((t: RawTLog) => ({
      baseUrl: t.baseUrl,
      hashAlgorithm: t.hashAlgorithm,
      publicKey: {
        rawBytes: t.publicKey.rawBytes,
        keyDetails: t.publicKey.keyDetails,
        validFor: t.publicKey.validFor,
      },
      logId: { keyId: t.logId.keyId },
    })),
    certificateAuthorities: raw.certificateAuthorities.map((ca: RawCA) => ({
      subject: ca.subject,
      uri: ca.uri,
      certChain: {
        certificates: ca.certChain.certificates.map((c: RawCert) => ({ rawBytes: c.rawBytes })),
      },
      validFor: ca.validFor,
    })),
    ctlogs: raw.ctlogs.map((ct: RawTLog) => ({
      baseUrl: ct.baseUrl,
      hashAlgorithm: ct.hashAlgorithm,
      publicKey: {
        rawBytes: ct.publicKey.rawBytes,
        keyDetails: ct.publicKey.keyDetails,
        validFor: ct.publicKey.validFor,
      },
      logId: { keyId: ct.logId.keyId },
    })),
    timestampAuthorities: raw.timestampAuthorities.map((tsa: RawCA) => ({
      subject: tsa.subject,
      uri: tsa.uri,
      certChain: {
        certificates: tsa.certChain.certificates.map((c: RawCert) => ({ rawBytes: c.rawBytes })),
      },
      validFor: tsa.validFor,
    })),
  };
}

const DEFAULT_OIDC_ISSUER = "https://token.actions.githubusercontent.com";
const DEFAULT_WORKFLOW_REF_PATTERN = /^refs\/tags\//;
const DEFAULT_TLOG_THRESHOLD = 1;
const DEFAULT_CTLOG_THRESHOLD = 1;
const DEFAULT_TIMESTAMP_THRESHOLD = 1;

const EMPTY_RESULT: SigstoreVerifyResult = {
  valid: false,
  predicateType: "",
  measurements: {},
  oidcIssuer: "",
  workflowRef: "",
  sourceRepo: "",
  logIndex: 0,
  integratedTime: 0,
};

/**
 * Verify a Sigstore bundle (cosign signature + Fulcio cert + Rekor log + CT log).
 * Returns a result object with `valid: true/false` — never throws.
 * On failure, `error` contains the message and `errorCode` contains the typed error code.
 */
export async function verifySigstoreBundle(
  bundle: unknown,
  opts: SigstoreVerifyOptions,
  trustedRoot?: TrustedRoot,
): Promise<SigstoreVerifyResult> {
  try {
    return await verifySigstoreBundleInternal(bundle, opts, trustedRoot);
  } catch (err) {
    if (err instanceof SigstoreError) {
      return { ...EMPTY_RESULT, error: err.message, errorCode: err.code };
    }
    return { ...EMPTY_RESULT, error: err instanceof Error ? err.message : String(err) };
  }
}

/** Internal verification — throws SigstoreError on failure. */
async function verifySigstoreBundleInternal(
  bundle: unknown,
  opts: SigstoreVerifyOptions,
  trustedRoot?: TrustedRoot,
): Promise<SigstoreVerifyResult> {
  const root =
    trustedRoot ?? (opts.liveTrustedRoot ? await fetchLiveTrustedRoot(opts.trustedRootUrl) : SIGSTORE_TRUSTED_ROOT);
  const oidcIssuer = opts.oidcIssuer ?? DEFAULT_OIDC_ISSUER;
  const workflowRefPattern = opts.workflowRefPattern ?? DEFAULT_WORKFLOW_REF_PATTERN;
  const tlogThreshold = opts.tlogThreshold ?? DEFAULT_TLOG_THRESHOLD;
  const ctlogThreshold = opts.ctlogThreshold ?? DEFAULT_CTLOG_THRESHOLD;
  const timestampThreshold = opts.timestampThreshold ?? DEFAULT_TIMESTAMP_THRESHOLD;

  // Validate thresholds — must be finite positive integers
  const validThreshold = (n: number) => Number.isFinite(n) && Number.isInteger(n) && n >= 1;
  if (!validThreshold(tlogThreshold) || !validThreshold(ctlogThreshold) || !validThreshold(timestampThreshold)) {
    throw new SigstoreError(
      "POLICY_ERROR",
      `Invalid threshold: tlog=${tlogThreshold}, ctlog=${ctlogThreshold}, timestamp=${timestampThreshold} (all must be finite integers >= 1)`,
    );
  }

  // Step 1: Parse bundle
  const parsed = parseBundle(bundle);

  // Step 2: Verify signing key (Fulcio cert chain)
  const { identity, signingKey } = await verifyFulcioCert(parsed.signingCert, root);

  // Step 3: Verify SCTs
  const sctCount = await verifySCTs(parsed.signingCert, root);
  if (sctCount < ctlogThreshold) {
    throw new SigstoreError("CERTIFICATE_ERROR", `Not enough verified SCTs: ${sctCount} < ${ctlogThreshold}`);
  }

  // Step 4: Verify transparency log entries — collect timestamps only from verified entries
  const verifiedTimestamps: Date[] = [];
  let verifiedTlogCount = 0;
  let firstVerifiedEntry: (typeof parsed.tlogEntries)[0] | undefined;
  for (const entry of parsed.tlogEntries) {
    try {
      await verifyTLogEntry(entry, parsed.envelope, root);
      verifiedTlogCount++;
      verifiedTimestamps.push(new Date(entry.integratedTime * 1000));
      if (!firstVerifiedEntry) firstVerifiedEntry = entry;
    } catch {
      // Entry verification failed — continue to check if threshold is met
    }
  }
  if (verifiedTlogCount < tlogThreshold) {
    throw new SigstoreError("TLOG_ERROR", `Not enough verified tlog entries: ${verifiedTlogCount} < ${tlogThreshold}`);
  }

  // Step 5: Collect RFC 3161 timestamps (CMS signature + TSA cert chain + artifact binding verified)
  if (parsed.rfc3161Timestamps.length > 0) {
    const rfc3161Dates = await verifyRFC3161Timestamps(parsed.rfc3161Timestamps, root, parsed.envelope.signature);
    verifiedTimestamps.push(...rfc3161Dates);
  }

  // Step 5b: Check timestamp threshold
  if (verifiedTimestamps.length < timestampThreshold) {
    throw new SigstoreError(
      "TIMESTAMP_ERROR",
      `Not enough verified timestamps: ${verifiedTimestamps.length} < ${timestampThreshold}`,
    );
  }

  // Step 5c: Verify at least one verified timestamp falls within signing cert validity
  const signingCertParsed = parseCertificate(parsed.signingCert);
  const validity = extractValidity(signingCertParsed.tbs);
  const hasValidTimestamp = verifiedTimestamps.some((ts) => ts >= validity.notBefore && ts <= validity.notAfter);
  if (!hasValidTimestamp) {
    throw new SigstoreError(
      "CERTIFICATE_ERROR",
      `No timestamp falls within signing cert validity window ` +
        `(${validity.notBefore.toISOString()} - ${validity.notAfter.toISOString()})`,
    );
  }

  // Step 6: Verify DSSE signature
  await verifyDSSESignature(parsed.envelope, signingKey);

  // Step 7: Verify policy
  if (identity.oidcIssuer !== oidcIssuer) {
    throw new SigstoreError(
      "POLICY_ERROR",
      `OIDC issuer mismatch: expected "${oidcIssuer}", got "${identity.oidcIssuer}"`,
    );
  }

  if (!matchRepoUri(identity.sourceRepoUri, opts.expectedRepo)) {
    throw new SigstoreError(
      "POLICY_ERROR",
      `Source repo mismatch: expected "${opts.expectedRepo}", got "${identity.sourceRepoUri}"`,
    );
  }

  if (!identity.sourceRepoRef) {
    throw new SigstoreError(
      "POLICY_ERROR",
      "Source repo ref missing from Fulcio certificate — cannot enforce workflow ref policy",
    );
  }
  if (!workflowRefPattern.test(identity.sourceRepoRef)) {
    throw new SigstoreError(
      "POLICY_ERROR",
      `Workflow ref "${identity.sourceRepoRef}" does not match pattern ${workflowRefPattern}`,
    );
  }

  // Step 8: Validate payload
  let payloadObj: Record<string, unknown>;
  try {
    payloadObj = JSON.parse(new TextDecoder().decode(parsed.envelope.payload));
  } catch {
    throw new SigstoreError("PAYLOAD_ERROR", "Failed to parse DSSE payload as JSON");
  }

  // Validate in-toto statement
  const subjects = payloadObj.subject as Array<Record<string, unknown>> | undefined;
  if (!subjects || subjects.length === 0) {
    throw new SigstoreError("PAYLOAD_ERROR", "No subjects in in-toto statement");
  }

  // Scan all subjects for matching digest (not just subjects[0])
  const matchingSubject = subjects.find((s) => (s.digest as Record<string, string>)?.sha256 === opts.expectedDigest);
  if (!matchingSubject) {
    const found = subjects.map((s) => (s.digest as Record<string, string>)?.sha256).filter(Boolean);
    throw new SigstoreError(
      "PAYLOAD_ERROR",
      `Digest mismatch: expected "${opts.expectedDigest}", found [${found.join(", ")}]`,
    );
  }

  // Extract measurements from predicate
  const predicateType = payloadObj.predicateType as string;

  if (opts.expectedPredicateType && predicateType !== opts.expectedPredicateType) {
    throw new SigstoreError(
      "PAYLOAD_ERROR",
      `Predicate type mismatch: expected "${opts.expectedPredicateType}", got "${predicateType}"`,
    );
  }

  const predicate = payloadObj.predicate as Record<string, unknown> | undefined;
  const measurements: CodeMeasurements = {};

  if (predicate) {
    if (predicate.snp_measurement) {
      measurements.snpMeasurement = predicate.snp_measurement as string;
    }
    const tdx = predicate.tdx_measurement as Record<string, string> | undefined;
    if (tdx) {
      if (tdx.rtmr1) measurements.tdxRtmr1 = tdx.rtmr1;
      if (tdx.rtmr2) measurements.tdxRtmr2 = tdx.rtmr2;
    }
  }

  // Step 9: Return result
  return {
    valid: true,
    predicateType: predicateType ?? "",
    measurements,
    oidcIssuer: identity.oidcIssuer,
    workflowRef: identity.sourceRepoRef,
    sourceRepo: identity.sourceRepoUri,
    logIndex: Number(firstVerifiedEntry?.logIndex ?? 0),
    integratedTime: firstVerifiedEntry?.integratedTime ?? 0,
  };
}

/**
 * Match a source repo URI against an expected repo identifier.
 *
 * If expectedRepo is a full URL (contains ://), requires exact match.
 * If expectedRepo is a short form (owner/repo), parses the URI and
 * requires github.com host + exact pathname match.
 */
function matchRepoUri(sourceRepoUri: string, expectedRepo: string): boolean {
  if (expectedRepo.includes("://")) {
    return sourceRepoUri === expectedRepo;
  }
  try {
    const uri = new URL(sourceRepoUri);
    if (uri.hostname !== "github.com") return false;
    return uri.pathname === `/${expectedRepo}`;
  } catch {
    return false;
  }
}
