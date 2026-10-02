// @atep/core: TypeScript API over the Rust atep-core compiled to WebAssembly.
//
// Call `await init()` once before anything else (or `initSync(bytes)`).

import rawInit, {
  initSync as rawInitSync,
  Identity as RawIdentity,
  agentIdOfBundle,
  parseAgentId as rawParseAgentId,
  sha256 as rawSha256,
  encrypt as rawEncrypt,
  encryptWithRandomness,
  view as rawView,
  submittedForm,
  withAttestations as rawWithAttestations,
  withInclusionProof as rawWithInclusionProof,
  merkleRoot as rawMerkleRoot,
  auditPath as rawAuditPath,
  verify as rawVerify,
  verifyAs as rawVerifyAs,
  verifyCheckpoint as rawVerifyCheckpoint,
  verifyInclusion as rawVerifyInclusion,
  checkConsistency as rawCheckConsistency,
  checkSplitView as rawCheckSplitView,
  verifySrl as rawVerifySrl,
  chainIdKind as rawChainIdKind,
  parseAnchorRecord as rawParseAnchorRecord,
  encodeAnchorRecord as rawEncodeAnchorRecord,
  checkpointHash as rawCheckpointHash,
  checkPublishedAnchor as rawCheckPublishedAnchor,
  parseRequireAnchor as rawParseRequireAnchor,
  checkAdmission as rawCheckAdmission,
  checkDomainBinding as rawCheckDomainBinding,
} from "./wasm/atep_wasm.js";

// ---------------------------------------------------------------------------
// Types

/** Bytes as hex text (lowercase) or a Uint8Array. */
export type HexOrBytes = string | Uint8Array;

/** A rejection: the verifier refused at `step` (spec section 10) with `error`. */
export interface Rejected {
  ok: false;
  step: number;
  error: string;
  cause?: { step: number; error: string };
}

export interface CheckpointInfo {
  log: string;
  tree_size: number;
  root_hash: string;
  timestamp: number;
}

export interface ChainLink {
  id: string;
  claim: string;
  subject: string;
  issuer: string;
  issued_at: number;
  expires_at: number;
}

export interface VerifiedClaim {
  claim: string;
  issuer: string;
  root: string;
  expires_at: number;
  chain: ChainLink[];
}

export interface Accepted {
  ok: true;
  signer: string;
  content_type: string;
  issued_at: number;
  expires_at: number | null;
  nonce_hex: string;
  encrypted: boolean;
  claims: VerifiedClaim[];
  checkpoint: CheckpointInfo | null;
  command_class?: string;
  warnings?: string[];
  payload_hex: string;
}

export type VerifyResult = Accepted | Rejected;

/** Trust policy (step 9), the policy file format of the Rust CLI. */
export interface TrustPolicy {
  roots?: string[];
  trusted_logs?: string[];
  max_depth?: number;
  /** Draft 04: when a rule fails with claim_missing, accept a one-hop `successor` attestation. Default false. */
  follow_succession?: boolean;
  require_inclusion?: boolean;
  atep_r?: boolean;
  srl?: { on_stale?: "fail-closed" | "fail-open"; on_missing?: "fail-closed" | "fail-open" };
  rules?: { claim: string; root?: string; max_age_days?: number }[];
}

export interface SeedsHex {
  ed25519: string;
  mldsa65: string;
  x25519?: string;
  mlkem768?: string;
}

/**
 * Verifier inputs besides the envelope and the clock. Same shape as the
 * `policy` object in the test vectors. Byte fields accept hex or Uint8Array.
 */
export interface VerifyPolicy {
  max_skew_secs?: number;
  known_bundles?: HexOrBytes[];
  seen_nonces?: HexOrBytes[];
  revocations?: { id: string; reason: "retired" | "compromised"; revoked_at: number }[];
  detached_payload_hex?: HexOrBytes;
  trust?: TrustPolicy;
  attestations?: HexOrBytes[];
  srls?: HexOrBytes[];
  /** Recipient seeds as JSON. Prefer passing `recipient` (an Identity) in the options. */
  recipient_seeds?: SeedsHex;
}

export interface VerifyOptions {
  /** Verification time, Unix seconds. Default: the current time. */
  now?: number;
  /** Identity that opens tag 96 envelopes. */
  recipient?: Identity;
}

export interface SignOptions {
  /** Default `application/atep+cbor`. */
  contentType?: string;
  /** Unix seconds. Default: now. */
  issuedAt?: number;
  expiresAt?: number | null;
  /** Payload travels out of band (nil in the envelope). */
  detached?: boolean;
  /** Embed the signer's public bundle. Default true. */
  includeBundle?: boolean;
  /** 16 bytes. Default: random. */
  nonce?: Uint8Array;
  /** FIPS 204 deterministic ML-DSA (reproducible, used for test vectors). Default: hedged. */
  deterministic?: boolean;
  /** ATEP-R command class. */
  commandClass?: string;
}

export interface AttestationOptions {
  /** Agent ID of the subject. */
  subject: string;
  /** Claim type, a full URI or a short name such as `operator-of`. */
  claim: string;
  issuedAt: number;
  expiresAt: number;
  /** Claim data as a JSON object; `{"$hex": "..."}` becomes a byte string. */
  data?: unknown;
  /** Claim data already CBOR encoded. */
  dataCbor?: Uint8Array;
  evidence?: Uint8Array;
  evidenceUri?: string;
  /** 16 byte attestation id. Default: random. */
  id?: Uint8Array;
  nonce?: Uint8Array;
  deterministic?: boolean;
  includeBundle?: boolean;
  allowLongDefault?: boolean;
}

export interface CheckpointOptions {
  treeSize: number;
  /** 32 byte root hash. */
  rootHash: Uint8Array;
  timestamp: number;
  nonce?: Uint8Array;
  deterministic?: boolean;
}

export interface SrlResult {
  ok: true;
  issuer: string;
  sequence: number;
  issued_at: number;
  next_update: number;
  stale: boolean;
  revoked: (
    | { kind: "attestation"; id_hex: string; reason: string; revoked_at: number }
    | { kind: "identity"; id: string; reason: string; revoked_at: number }
  )[];
  warnings?: string[];
}

export type CheckpointResult = { ok: true; checkpoint: CheckpointInfo } | Rejected;
export type OldNewResult = { ok: true; old: CheckpointInfo; new: CheckpointInfo } | Rejected;
export type PairResult = { ok: true; a: CheckpointInfo; b: CheckpointInfo } | Rejected;

// ---------------------------------------------------------------------------
// Initialisation

let ready = false;

export type WasmSource =
  | Uint8Array
  | ArrayBuffer
  | WebAssembly.Module
  | URL
  | string
  | Response
  | Promise<Response>;

/**
 * Load the wasm module. Without an argument the binary is found next to this
 * file: read from disk for `file:` URLs (Node, Bun, Deno), fetched otherwise
 * (browsers, bundlers that rewrite `import.meta.url`). Pass bytes, a URL or a
 * `Response` to override. Safe to call more than once.
 */
export async function init(source?: WasmSource): Promise<void> {
  if (ready) return;
  let input: unknown = source;
  if (input === undefined) {
    const url = new URL("./wasm/atep_wasm_bg.wasm", import.meta.url);
    if (url.protocol === "file:") {
      const { readFile } = await import("node:fs/promises");
      input = await readFile(url);
    } else {
      input = url;
    }
  }
  if (input instanceof Uint8Array) {
    rawInitSync({ module: input });
  } else {
    await rawInit({ module_or_path: input as never });
  }
  ready = true;
}

/** Synchronous initialisation from wasm bytes or a compiled module. */
export function initSync(source: Uint8Array | ArrayBuffer | WebAssembly.Module): void {
  if (ready) return;
  rawInitSync({ module: source as never });
  ready = true;
}

function need(): void {
  if (!ready) throw new Error("@atep/core: call `await init()` first");
}

// ---------------------------------------------------------------------------
// Helpers

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || /[^0-9a-fA-F]/.test(hex)) throw new Error("invalid hex");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesToHex(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

const hx = (v: HexOrBytes): string => (typeof v === "string" ? v : bytesToHex(v));
const nowSecs = (): number => Math.floor(Date.now() / 1000);

function normalizePolicy(p: VerifyPolicy): string {
  const o: Record<string, unknown> = { ...p };
  for (const k of ["known_bundles", "seen_nonces", "attestations", "srls"] as const) {
    const v = p[k];
    if (v !== undefined) o[k] = v.map(hx);
  }
  if (p.detached_payload_hex !== undefined) o.detached_payload_hex = hx(p.detached_payload_hex);
  return JSON.stringify(o);
}

function signJson(o: SignOptions): string {
  const j: Record<string, unknown> = {
    content_type: o.contentType,
    issued_at: o.issuedAt ?? nowSecs(),
    expires_at: o.expiresAt ?? undefined,
    detached: o.detached,
    include_bundle: o.includeBundle,
    nonce_hex: o.nonce && bytesToHex(o.nonce),
    mode: o.deterministic ? "deterministic" : "hedged",
    command_class: o.commandClass,
  };
  return JSON.stringify(j);
}

// ---------------------------------------------------------------------------
// Identity

export interface SeedBytes {
  ed25519: Uint8Array;
  mldsa65: Uint8Array;
  x25519?: Uint8Array;
  mlkem768?: Uint8Array;
}

/**
 * An agent identity. Its secret seeds live in wasm linear memory and are
 * zeroized when the object is freed. Call `free()` (or use `using`) when done.
 */
export class Identity {
  readonly #raw: RawIdentity;

  private constructor(raw: RawIdentity) {
    this.#raw = raw;
  }

  /** Generate a new identity. `encryption` adds X25519 and ML-KEM-768 keys (needed to receive encrypted envelopes). */
  static generate(encryption = true): Identity {
    need();
    return new Identity(RawIdentity.generate(encryption));
  }

  /** From raw seeds (the same values the test vectors list). */
  static fromSeeds(seeds: SeedBytes): Identity {
    need();
    return new Identity(
      RawIdentity.fromSeeds(seeds.ed25519, seeds.mldsa65, seeds.x25519 ?? null, seeds.mlkem768 ?? null),
    );
  }

  /** From seeds given as hex (the format of the vector `inputs`). */
  static fromSeedsHex(s: SeedsHex): Identity {
    return Identity.fromSeeds({
      ed25519: hexToBytes(s.ed25519),
      mldsa65: hexToBytes(s.mldsa65),
      x25519: s.x25519 ? hexToBytes(s.x25519) : undefined,
      mlkem768: s.mlkem768 ? hexToBytes(s.mlkem768) : undefined,
    });
  }

  /** From the CBOR secret key file written by `exportSecret` or the Rust CLI. */
  static fromSecret(secret: Uint8Array): Identity {
    need();
    return new Identity(RawIdentity.fromSecret(secret));
  }

  /** The secret key file. The returned array holds secrets: `fill(0)` it when done. */
  exportSecret(): Uint8Array {
    return this.#raw.exportSecret();
  }

  /** Agent ID, `atep:...`. */
  get agentId(): string {
    return this.#raw.agentId();
  }
  get agentIdBytes(): Uint8Array {
    return this.#raw.agentIdBytes();
  }
  get did(): string {
    return this.#raw.did();
  }
  get publicBundle(): Uint8Array {
    return this.#raw.publicBundle();
  }
  get hasEncryption(): boolean {
    return this.#raw.hasEncryption();
  }

  /** Sign a payload into a tag 98 envelope (Ed25519 plus ML-DSA-65). */
  sign(payload: Uint8Array, options: SignOptions = {}): Uint8Array {
    return this.#raw.sign(payload, signJson(options));
  }

  /** Open a tag 96 envelope addressed to this identity. Returns the inner signed envelope, unverified. */
  decrypt(data: Uint8Array): Uint8Array {
    return this.#raw.decrypt(data);
  }

  /** Issue an attestation (spec section 7) about `options.subject`. */
  issueAttestation(o: AttestationOptions): Uint8Array {
    return this.#raw.issueAttestation(
      JSON.stringify({
        subject: o.subject,
        claim: o.claim,
        issued_at: o.issuedAt,
        expires_at: o.expiresAt,
        data: o.data,
        data_hex: o.dataCbor && bytesToHex(o.dataCbor),
        evidence_hex: o.evidence && bytesToHex(o.evidence),
        evidence_uri: o.evidenceUri,
        id_hex: o.id && bytesToHex(o.id),
        nonce_hex: o.nonce && bytesToHex(o.nonce),
        mode: o.deterministic ? "deterministic" : "hedged",
        include_bundle: o.includeBundle,
        allow_long_default: o.allowLongDefault,
      }),
    );
  }

  /** Create a signed revocation list with this identity as issuer (spec section 8). */
  createSrl(o: {
    sequence: number;
    issuedAt: number;
    nextUpdate: number;
    revoked: Array<
      ({ attestationId: Uint8Array } | { identity: string }) & { reason: string; revokedAt: number }
    >;
    nonce?: Uint8Array;
    deterministic?: boolean;
    includeBundle?: boolean;
  }): Uint8Array {
    return this.#raw.createSrl(
      JSON.stringify({
        sequence: o.sequence,
        issued_at: o.issuedAt,
        next_update: o.nextUpdate,
        revoked: o.revoked.map((r) => ({
          ...("attestationId" in r ? { id_hex: bytesToHex(r.attestationId) } : { id: r.identity }),
          reason: r.reason,
          revoked_at: r.revokedAt,
        })),
        nonce_hex: o.nonce && bytesToHex(o.nonce),
        mode: o.deterministic ? "deterministic" : "hedged",
        include_bundle: o.includeBundle,
      }),
    );
  }

  /** Sign a log checkpoint with this identity as the log. */
  createCheckpoint(o: CheckpointOptions): Uint8Array {
    return this.#raw.createCheckpoint(
      JSON.stringify({
        tree_size: o.treeSize,
        root_hash_hex: bytesToHex(o.rootHash),
        timestamp: o.timestamp,
        nonce_hex: o.nonce && bytesToHex(o.nonce),
        mode: o.deterministic ? "deterministic" : "hedged",
      }),
    );
  }

  /** Verify with this identity as the recipient (opens tag 96 envelopes). */
  verify(data: Uint8Array, policy: VerifyPolicy = {}, now: number = nowSecs()): VerifyResult {
    return JSON.parse(rawVerifyAs(this.#raw, data, normalizePolicy(policy), now));
  }

  /** Zeroize and release the secret seeds. */
  free(): void {
    this.#raw.free();
  }
  [Symbol.dispose](): void {
    this.#raw.free();
  }
}

// ---------------------------------------------------------------------------
// Functions

/** Generate an identity (alias of `Identity.generate`). */
export function keygen(encryption = true): Identity {
  return Identity.generate(encryption);
}

/** Agent ID of a public bundle (or of an Identity). */
export function agentId(bundleOrIdentity: Uint8Array | Identity): string {
  need();
  return bundleOrIdentity instanceof Identity
    ? bundleOrIdentity.agentId
    : agentIdOfBundle(bundleOrIdentity);
}

/** Parse an Agent ID in `atep:` or `did:atep:` form. */
export function parseAgentId(s: string): { text: string; did: string; hex: string } {
  need();
  return JSON.parse(rawParseAgentId(s));
}

export function sign(identity: Identity, payload: Uint8Array, options: SignOptions = {}): Uint8Array {
  return identity.sign(payload, options);
}

/** Encrypt a signed envelope to a recipient's public bundle (hybrid X25519 + ML-KEM-768, AES-256-GCM). */
export function encrypt(signedEnvelope: Uint8Array, recipientBundle: Uint8Array): Uint8Array {
  need();
  return rawEncrypt(signedEnvelope, recipientBundle);
}

/** Encrypt with explicit randomness. Only for reproducing test vectors. */
export function encryptDeterministic(
  signedEnvelope: Uint8Array,
  recipientBundle: Uint8Array,
  rnd: { x25519Ephemeral: Uint8Array; mlkemM: Uint8Array; iv: Uint8Array },
): Uint8Array {
  need();
  return encryptWithRandomness(signedEnvelope, recipientBundle, rnd.x25519Ephemeral, rnd.mlkemM, rnd.iv);
}

export function decrypt(identity: Identity, data: Uint8Array): Uint8Array {
  return identity.decrypt(data);
}

/**
 * Verify an envelope, spec section 10 steps 1 to 10. A rejection is returned
 * as `{ok: false, step, error}`, not thrown. Malformed arguments throw.
 */
export function verify(data: Uint8Array, policy: VerifyPolicy = {}, options: VerifyOptions = {}): VerifyResult {
  need();
  const now = options.now ?? nowSecs();
  if (options.recipient) return options.recipient.verify(data, policy, now);
  return JSON.parse(rawVerify(data, normalizePolicy(policy), now));
}

/** JSON debug rendering of any ATEP CBOR object (envelope, bundle, ...). Not canonical. */
export function view(data: Uint8Array): unknown {
  need();
  return JSON.parse(rawView(data));
}

export function sha256(data: Uint8Array): Uint8Array {
  need();
  return rawSha256(data);
}

/** Put inline attestations into the (unsigned) unprotected header of an envelope. */
export function withAttestations(envelope: Uint8Array, attestations: Uint8Array[]): Uint8Array {
  need();
  return rawWithAttestations(envelope, JSON.stringify(attestations.map(bytesToHex)));
}

/** Attach a log inclusion proof to an attestation. */
export function withInclusionProof(
  attestation: Uint8Array,
  proof: { leafIndex: number; auditPath: Uint8Array[]; checkpoint: Uint8Array },
): Uint8Array {
  need();
  return rawWithInclusionProof(
    attestation,
    proof.leafIndex,
    JSON.stringify(proof.auditPath.map(bytesToHex)),
    proof.checkpoint,
  );
}

/** The attestation as submitted to a log: its inclusion proof header removed. This is the Merkle leaf. */
export function submittedFormOf(attestation: Uint8Array): Uint8Array {
  need();
  return submittedForm(attestation);
}

/** RFC 9162 Merkle root over leaves. */
export function merkleRoot(leaves: Uint8Array[]): Uint8Array {
  need();
  return hexToBytes(rawMerkleRoot(JSON.stringify(leaves.map(bytesToHex))));
}

/** RFC 9162 audit path of leaf `index`. */
export function auditPath(index: number, leaves: Uint8Array[]): Uint8Array[] {
  need();
  return (JSON.parse(rawAuditPath(index, JSON.stringify(leaves.map(bytesToHex)))) as string[]).map(hexToBytes);
}

/** Verify a checkpoint envelope: steps 1 to 8, content type, trusted log, schema. */
export function verifyCheckpoint(cbor: Uint8Array, trustedLogs: string[], now: number = nowSecs()): CheckpointResult {
  need();
  return JSON.parse(rawVerifyCheckpoint(cbor, JSON.stringify(trustedLogs), now));
}

/** Verify the inclusion proof an attestation carries (offline, against trusted logs). */
export function verifyInclusion(attestation: Uint8Array, trustedLogs: string[], now: number = nowSecs()): CheckpointResult {
  need();
  return JSON.parse(rawVerifyInclusion(attestation, JSON.stringify(trustedLogs), now));
}

/** Check a consistency proof document `{old, new, proof}` (CBOR). */
export function checkConsistency(cbor: Uint8Array, trustedLogs: string[], now: number = nowSecs()): OldNewResult {
  need();
  return JSON.parse(rawCheckConsistency(cbor, JSON.stringify(trustedLogs), now));
}

/** Check a split view document `{a, b, proof?}` (CBOR). */
export function checkSplitView(cbor: Uint8Array, trustedLogs: string[], now: number = nowSecs()): PairResult {
  need();
  return JSON.parse(rawCheckSplitView(cbor, JSON.stringify(trustedLogs), now));
}

/**
 * The verifier's own context for loading an SRL (Draft 04, spec section 8): the
 * cached list and the list are loaded with steps 1 to 8 against these.
 * `attestations` is the local store (step 8 reads valid `retired` attestations
 * from it), `revocations` the directly supplied identity revocations.
 */
export interface SrlContext {
  known_bundles?: HexOrBytes[];
  attestations?: HexOrBytes[];
  revocations?: { id: string; reason: "retired" | "compromised"; revoked_at: number }[];
  max_skew_secs?: number;
}

function normalizeSrlContext(c: SrlContext): string {
  const o: Record<string, unknown> = { ...c };
  for (const k of ["known_bundles", "attestations"] as const) {
    const v = c[k];
    if (v !== undefined) o[k] = v.map(hx);
  }
  return JSON.stringify(o);
}

/**
 * Verify a signed revocation list and apply the freshness rule. `cached` is a
 * previously accepted SRL of the same issuer (rollback and conflict rules apply).
 */
export function verifySrl(
  srl: Uint8Array,
  options: { now?: number; onStale?: "fail-closed" | "fail-open"; cached?: Uint8Array; context?: SrlContext } = {},
): SrlResult | Rejected {
  need();
  return JSON.parse(
    rawVerifySrl(
      srl,
      options.now ?? nowSecs(),
      JSON.stringify({ on_stale: options.onStale ?? "fail-closed" }),
      options.cached ?? undefined,
      options.context ? normalizeSrlContext(options.context) : undefined,
    ),
  );
}

// ---------------------------------------------------------------------------
// Draft 05: anchors, chain ids, require_anchor, admission, domain binding

/** A decoded anchor record (spec section 9). `block_height` is null when absent. */
export interface AnchorRecordInfo {
  checkpoint_hash: string;
  chain_id: string;
  transaction_id: string;
  block_height: number | null;
  anchored_at: number;
}

/** One parsed `require_anchor` rule: exactly one of the two age members is set. */
export interface AnchorRuleInfo {
  log: string;
  chain: string;
  max_age_days?: number;
  max_age_hours?: number;
}

export type ChainIdResult = { ok: true; kind: "registered" | "extension" } | { ok: false };
export type AnchorRecordResult = { ok: true; record: AnchorRecordInfo } | { ok: false; error: "anchor_record_invalid" };
export type CheckpointHashResult =
  | { ok: true; checkpoint: CheckpointInfo; checkpoint_hash: string; payload_hex: string }
  | Rejected;
export type PublishedAnchorResult = { ok: true; log: string; record: AnchorRecordInfo } | Rejected;
export type RequireAnchorResult =
  | { ok: true; require_anchor: AnchorRuleInfo[] }
  | { ok: false; error: "policy_invalid" };
export type AdmissionResult =
  | { ok: true; document: "attestation" | "srl" }
  | { ok: false; refusal: string; step?: number; error?: string };

/** The state of one domain record source (`not-read` when the check never asked for it). */
export type DomainSourceState = "listed" | "not-listed" | "absent" | "invalid" | "unavailable" | "not-read";

/** A fetcher answer for the well-known document. `body_filler` stands for a large body. */
export type WellKnownAnswer =
  | { unavailable: string }
  | {
      status: number;
      final_url?: string;
      content_type?: string | null;
      body?: string;
      body_filler?: { prefix: string; fill: string; suffix: string; total_bytes: number };
    };
export type TxtFixtureAnswer = { unavailable: string } | { records: (string | string[])[]; dnssec_validated?: boolean };

/** Input of `checkDomainBinding`: what a fake fetcher answers, by host and by TXT name. No network is used. */
export interface DomainBindingFixture {
  domain: string;
  agent_id: string;
  options?: { require_both?: boolean; require_dnssec?: boolean };
  well_known: Record<string, WellKnownAnswer>;
  txt: Record<string, TxtFixtureAnswer>;
}

export interface DomainBindingResult {
  well_known: DomainSourceState;
  dns: DomainSourceState;
  outcome: "bound" | "not-bound" | "indeterminate";
  queried: { well_known: string[]; txt: string[] };
}

/** Is `id` a valid `chain-id`: one of the five registered ids, or `x-` plus a lowercase name. Pure function. */
export function chainIdKind(id: string): ChainIdResult {
  need();
  return JSON.parse(rawChainIdKind(id));
}

/** Decode an anchor record payload (strict deterministic CBOR). Invalid input is a result, not an exception. */
export function parseAnchorRecord(payload: Uint8Array): AnchorRecordResult {
  need();
  return JSON.parse(rawParseAnchorRecord(payload));
}

/** Deterministic CBOR of an anchor record (no `block-height` key when it is null or absent). */
export function encodeAnchorRecord(record: Omit<AnchorRecordInfo, "block_height"> & { block_height?: number | null }): Uint8Array {
  need();
  return rawEncodeAnchorRecord(JSON.stringify(record));
}

/** Verify a checkpoint envelope (as `verifyCheckpoint`) and add `checkpoint_hash`: SHA-256 of the verified payload. */
export function checkpointHash(cbor: Uint8Array, trustedLogs: string[], now: number = nowSecs()): CheckpointHashResult {
  need();
  return JSON.parse(rawCheckpointHash(cbor, JSON.stringify(trustedLogs), now));
}

/**
 * Take a log-signed anchor envelope as published: steps 1 to 8 (reported as they are), then the content
 * type, the record schema, the signer (`log`) and the checkpoint hash (hex), in that order.
 * Whether the witness really holds the hash is not checked.
 */
export function checkPublishedAnchor(
  envelope: Uint8Array,
  log: string,
  checkpointHashHex: string,
  now: number = nowSecs(),
): PublishedAnchorResult {
  need();
  return JSON.parse(rawCheckPublishedAnchor(envelope, log, checkpointHashHex, now));
}

/** Parse the `require_anchor` rules of a trust policy object. A bad policy is `{ok: false, error: "policy_invalid"}`. */
export function parseRequireAnchor(policy: unknown): RequireAnchorResult {
  need();
  return JSON.parse(rawParseRequireAnchor(JSON.stringify(policy)));
}

/**
 * The admission rules of a log (spec section 9) applied to one submission, including the data rules of
 * `registry-endpoint` and `domain-control`. `logged` are documents admitted first, in order (hex or bytes).
 * This package has no log: this is a pure check of the rules.
 */
export function checkAdmission(
  submission: Uint8Array,
  options: { now?: number; log: string; maxEnvelopeBytes?: number; logged?: HexOrBytes[] },
): AdmissionResult {
  need();
  return JSON.parse(
    rawCheckAdmission(
      submission,
      JSON.stringify({
        now: options.now ?? nowSecs(),
        log: options.log,
        max_envelope_bytes: options.maxEnvelopeBytes ?? 65536,
        logged: (options.logged ?? []).map(hx),
      }),
    ),
  );
}

/** Run the domain binding check (section 7) over a fixture of fetcher answers. No network is used. */
export function checkDomainBinding(fixture: DomainBindingFixture): DomainBindingResult {
  need();
  return JSON.parse(rawCheckDomainBinding(JSON.stringify(fixture)));
}
