/** Bytes as hex text (lowercase) or a Uint8Array. */
export type HexOrBytes = string | Uint8Array;
/** A rejection: the verifier refused at `step` (spec section 10) with `error`. */
export interface Rejected {
    ok: false;
    step: number;
    error: string;
    cause?: {
        step: number;
        error: string;
    };
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
    srl?: {
        on_stale?: "fail-closed" | "fail-open";
        on_missing?: "fail-closed" | "fail-open";
    };
    rules?: {
        claim: string;
        root?: string;
        max_age_days?: number;
    }[];
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
    revocations?: {
        id: string;
        reason: "retired" | "compromised";
        revoked_at: number;
    }[];
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
    revoked: ({
        kind: "attestation";
        id_hex: string;
        reason: string;
        revoked_at: number;
    } | {
        kind: "identity";
        id: string;
        reason: string;
        revoked_at: number;
    })[];
    warnings?: string[];
}
export type CheckpointResult = {
    ok: true;
    checkpoint: CheckpointInfo;
} | Rejected;
export type OldNewResult = {
    ok: true;
    old: CheckpointInfo;
    new: CheckpointInfo;
} | Rejected;
export type PairResult = {
    ok: true;
    a: CheckpointInfo;
    b: CheckpointInfo;
} | Rejected;
export type WasmSource = Uint8Array | ArrayBuffer | WebAssembly.Module | URL | string | Response | Promise<Response>;
/**
 * Load the wasm module. Without an argument the binary is found next to this
 * file: read from disk for `file:` URLs (Node, Bun, Deno), fetched otherwise
 * (browsers, bundlers that rewrite `import.meta.url`). Pass bytes, a URL or a
 * `Response` to override. Safe to call more than once.
 */
export declare function init(source?: WasmSource): Promise<void>;
/** Synchronous initialisation from wasm bytes or a compiled module. */
export declare function initSync(source: Uint8Array | ArrayBuffer | WebAssembly.Module): void;
export declare function hexToBytes(hex: string): Uint8Array;
export declare function bytesToHex(b: Uint8Array): string;
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
export declare class Identity {
    #private;
    private constructor();
    /** Generate a new identity. `encryption` adds X25519 and ML-KEM-768 keys (needed to receive encrypted envelopes). */
    static generate(encryption?: boolean): Identity;
    /** From raw seeds (the same values the test vectors list). */
    static fromSeeds(seeds: SeedBytes): Identity;
    /** From seeds given as hex (the format of the vector `inputs`). */
    static fromSeedsHex(s: SeedsHex): Identity;
    /** From the CBOR secret key file written by `exportSecret` or the Rust CLI. */
    static fromSecret(secret: Uint8Array): Identity;
    /** The secret key file. The returned array holds secrets: `fill(0)` it when done. */
    exportSecret(): Uint8Array;
    /** Agent ID, `atep:...`. */
    get agentId(): string;
    get agentIdBytes(): Uint8Array;
    get did(): string;
    get publicBundle(): Uint8Array;
    get hasEncryption(): boolean;
    /** Sign a payload into a tag 98 envelope (Ed25519 plus ML-DSA-65). */
    sign(payload: Uint8Array, options?: SignOptions): Uint8Array;
    /** Open a tag 96 envelope addressed to this identity. Returns the inner signed envelope, unverified. */
    decrypt(data: Uint8Array): Uint8Array;
    /** Issue an attestation (spec section 7) about `options.subject`. */
    issueAttestation(o: AttestationOptions): Uint8Array;
    /** Create a signed revocation list with this identity as issuer (spec section 8). */
    createSrl(o: {
        sequence: number;
        issuedAt: number;
        nextUpdate: number;
        revoked: Array<({
            attestationId: Uint8Array;
        } | {
            identity: string;
        }) & {
            reason: string;
            revokedAt: number;
        }>;
        nonce?: Uint8Array;
        deterministic?: boolean;
        includeBundle?: boolean;
    }): Uint8Array;
    /** Sign a log checkpoint with this identity as the log. */
    createCheckpoint(o: CheckpointOptions): Uint8Array;
    /** Verify with this identity as the recipient (opens tag 96 envelopes). */
    verify(data: Uint8Array, policy?: VerifyPolicy, now?: number): VerifyResult;
    /** Zeroize and release the secret seeds. */
    free(): void;
    [Symbol.dispose](): void;
}
/** Generate an identity (alias of `Identity.generate`). */
export declare function keygen(encryption?: boolean): Identity;
/** Agent ID of a public bundle (or of an Identity). */
export declare function agentId(bundleOrIdentity: Uint8Array | Identity): string;
/** Parse an Agent ID in `atep:` or `did:atep:` form. */
export declare function parseAgentId(s: string): {
    text: string;
    did: string;
    hex: string;
};
export declare function sign(identity: Identity, payload: Uint8Array, options?: SignOptions): Uint8Array;
/** Encrypt a signed envelope to a recipient's public bundle (hybrid X25519 + ML-KEM-768, AES-256-GCM). */
export declare function encrypt(signedEnvelope: Uint8Array, recipientBundle: Uint8Array): Uint8Array;
/** Encrypt with explicit randomness. Only for reproducing test vectors. */
export declare function encryptDeterministic(signedEnvelope: Uint8Array, recipientBundle: Uint8Array, rnd: {
    x25519Ephemeral: Uint8Array;
    mlkemM: Uint8Array;
    iv: Uint8Array;
}): Uint8Array;
export declare function decrypt(identity: Identity, data: Uint8Array): Uint8Array;
/**
 * Verify an envelope, spec section 10 steps 1 to 10. A rejection is returned
 * as `{ok: false, step, error}`, not thrown. Malformed arguments throw.
 */
export declare function verify(data: Uint8Array, policy?: VerifyPolicy, options?: VerifyOptions): VerifyResult;
/** JSON debug rendering of any ATEP CBOR object (envelope, bundle, ...). Not canonical. */
export declare function view(data: Uint8Array): unknown;
export declare function sha256(data: Uint8Array): Uint8Array;
/** Put inline attestations into the (unsigned) unprotected header of an envelope. */
export declare function withAttestations(envelope: Uint8Array, attestations: Uint8Array[]): Uint8Array;
/** Attach a log inclusion proof to an attestation. */
export declare function withInclusionProof(attestation: Uint8Array, proof: {
    leafIndex: number;
    auditPath: Uint8Array[];
    checkpoint: Uint8Array;
}): Uint8Array;
/** The attestation as submitted to a log: its inclusion proof header removed. This is the Merkle leaf. */
export declare function submittedFormOf(attestation: Uint8Array): Uint8Array;
/** RFC 9162 Merkle root over leaves. */
export declare function merkleRoot(leaves: Uint8Array[]): Uint8Array;
/** RFC 9162 audit path of leaf `index`. */
export declare function auditPath(index: number, leaves: Uint8Array[]): Uint8Array[];
/** Verify a checkpoint envelope: steps 1 to 8, content type, trusted log, schema. */
export declare function verifyCheckpoint(cbor: Uint8Array, trustedLogs: string[], now?: number): CheckpointResult;
/** Verify the inclusion proof an attestation carries (offline, against trusted logs). */
export declare function verifyInclusion(attestation: Uint8Array, trustedLogs: string[], now?: number): CheckpointResult;
/** Check a consistency proof document `{old, new, proof}` (CBOR). */
export declare function checkConsistency(cbor: Uint8Array, trustedLogs: string[], now?: number): OldNewResult;
/** Check a split view document `{a, b, proof?}` (CBOR). */
export declare function checkSplitView(cbor: Uint8Array, trustedLogs: string[], now?: number): PairResult;
/**
 * The verifier's own context for loading an SRL (Draft 04, spec section 8): the
 * cached list and the list are loaded with steps 1 to 8 against these.
 * `attestations` is the local store (step 8 reads valid `retired` attestations
 * from it), `revocations` the directly supplied identity revocations.
 */
export interface SrlContext {
    known_bundles?: HexOrBytes[];
    attestations?: HexOrBytes[];
    revocations?: {
        id: string;
        reason: "retired" | "compromised";
        revoked_at: number;
    }[];
    max_skew_secs?: number;
}
/**
 * Verify a signed revocation list and apply the freshness rule. `cached` is a
 * previously accepted SRL of the same issuer (rollback and conflict rules apply).
 */
export declare function verifySrl(srl: Uint8Array, options?: {
    now?: number;
    onStale?: "fail-closed" | "fail-open";
    cached?: Uint8Array;
    context?: SrlContext;
}): SrlResult | Rejected;
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
export type ChainIdResult = {
    ok: true;
    kind: "registered" | "extension";
} | {
    ok: false;
};
export type AnchorRecordResult = {
    ok: true;
    record: AnchorRecordInfo;
} | {
    ok: false;
    error: "anchor_record_invalid";
};
export type CheckpointHashResult = {
    ok: true;
    checkpoint: CheckpointInfo;
    checkpoint_hash: string;
    payload_hex: string;
} | Rejected;
export type PublishedAnchorResult = {
    ok: true;
    log: string;
    record: AnchorRecordInfo;
} | Rejected;
export type RequireAnchorResult = {
    ok: true;
    require_anchor: AnchorRuleInfo[];
} | {
    ok: false;
    error: "policy_invalid";
};
export type AdmissionResult = {
    ok: true;
    document: "attestation" | "srl";
} | {
    ok: false;
    refusal: string;
    step?: number;
    error?: string;
};
/** The state of one domain record source (`not-read` when the check never asked for it). */
export type DomainSourceState = "listed" | "not-listed" | "absent" | "invalid" | "unavailable" | "not-read";
/** A fetcher answer for the well-known document. `body_filler` stands for a large body. */
export type WellKnownAnswer = {
    unavailable: string;
} | {
    status: number;
    final_url?: string;
    content_type?: string | null;
    body?: string;
    body_filler?: {
        prefix: string;
        fill: string;
        suffix: string;
        total_bytes: number;
    };
};
export type TxtFixtureAnswer = {
    unavailable: string;
} | {
    records: (string | string[])[];
    dnssec_validated?: boolean;
};
/** Input of `checkDomainBinding`: what a fake fetcher answers, by host and by TXT name. No network is used. */
export interface DomainBindingFixture {
    domain: string;
    agent_id: string;
    options?: {
        require_both?: boolean;
        require_dnssec?: boolean;
    };
    well_known: Record<string, WellKnownAnswer>;
    txt: Record<string, TxtFixtureAnswer>;
}
export interface DomainBindingResult {
    well_known: DomainSourceState;
    dns: DomainSourceState;
    outcome: "bound" | "not-bound" | "indeterminate";
    queried: {
        well_known: string[];
        txt: string[];
    };
}
/** Is `id` a valid `chain-id`: one of the five registered ids, or `x-` plus a lowercase name. Pure function. */
export declare function chainIdKind(id: string): ChainIdResult;
/** Decode an anchor record payload (strict deterministic CBOR). Invalid input is a result, not an exception. */
export declare function parseAnchorRecord(payload: Uint8Array): AnchorRecordResult;
/** Deterministic CBOR of an anchor record (no `block-height` key when it is null or absent). */
export declare function encodeAnchorRecord(record: Omit<AnchorRecordInfo, "block_height"> & {
    block_height?: number | null;
}): Uint8Array;
/** Verify a checkpoint envelope (as `verifyCheckpoint`) and add `checkpoint_hash`: SHA-256 of the verified payload. */
export declare function checkpointHash(cbor: Uint8Array, trustedLogs: string[], now?: number): CheckpointHashResult;
/**
 * Take a log-signed anchor envelope as published: steps 1 to 8 (reported as they are), then the content
 * type, the record schema, the signer (`log`) and the checkpoint hash (hex), in that order.
 * Whether the witness really holds the hash is not checked.
 */
export declare function checkPublishedAnchor(envelope: Uint8Array, log: string, checkpointHashHex: string, now?: number): PublishedAnchorResult;
/** Parse the `require_anchor` rules of a trust policy object. A bad policy is `{ok: false, error: "policy_invalid"}`. */
export declare function parseRequireAnchor(policy: unknown): RequireAnchorResult;
/**
 * The admission rules of a log (spec section 9) applied to one submission, including the data rules of
 * `registry-endpoint` and `domain-control`. `logged` are documents admitted first, in order (hex or bytes).
 * This package has no log: this is a pure check of the rules.
 */
export declare function checkAdmission(submission: Uint8Array, options: {
    now?: number;
    log: string;
    maxEnvelopeBytes?: number;
    logged?: HexOrBytes[];
}): AdmissionResult;
/** Run the domain binding check (section 7) over a fixture of fetcher answers. No network is used. */
export declare function checkDomainBinding(fixture: DomainBindingFixture): DomainBindingResult;
