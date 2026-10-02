// @atep/core: TypeScript API over the Rust atep-core compiled to WebAssembly.
//
// Call `await init()` once before anything else (or `initSync(bytes)`).
import rawInit, { initSync as rawInitSync, Identity as RawIdentity, agentIdOfBundle, parseAgentId as rawParseAgentId, sha256 as rawSha256, encrypt as rawEncrypt, encryptWithRandomness, view as rawView, submittedForm, withAttestations as rawWithAttestations, withInclusionProof as rawWithInclusionProof, merkleRoot as rawMerkleRoot, auditPath as rawAuditPath, verify as rawVerify, verifyAs as rawVerifyAs, verifyCheckpoint as rawVerifyCheckpoint, verifyInclusion as rawVerifyInclusion, checkConsistency as rawCheckConsistency, checkSplitView as rawCheckSplitView, verifySrl as rawVerifySrl, chainIdKind as rawChainIdKind, parseAnchorRecord as rawParseAnchorRecord, encodeAnchorRecord as rawEncodeAnchorRecord, checkpointHash as rawCheckpointHash, checkPublishedAnchor as rawCheckPublishedAnchor, parseRequireAnchor as rawParseRequireAnchor, checkAdmission as rawCheckAdmission, checkDomainBinding as rawCheckDomainBinding, } from "./wasm/atep_wasm.js";
// ---------------------------------------------------------------------------
// Initialisation
let ready = false;
/**
 * Load the wasm module. Without an argument the binary is found next to this
 * file: read from disk for `file:` URLs (Node, Bun, Deno), fetched otherwise
 * (browsers, bundlers that rewrite `import.meta.url`). Pass bytes, a URL or a
 * `Response` to override. Safe to call more than once.
 */
export async function init(source) {
    if (ready)
        return;
    let input = source;
    if (input === undefined) {
        const url = new URL("./wasm/atep_wasm_bg.wasm", import.meta.url);
        if (url.protocol === "file:") {
            const { readFile } = await import("node:fs/promises");
            input = await readFile(url);
        }
        else {
            input = url;
        }
    }
    if (input instanceof Uint8Array) {
        rawInitSync({ module: input });
    }
    else {
        await rawInit({ module_or_path: input });
    }
    ready = true;
}
/** Synchronous initialisation from wasm bytes or a compiled module. */
export function initSync(source) {
    if (ready)
        return;
    rawInitSync({ module: source });
    ready = true;
}
function need() {
    if (!ready)
        throw new Error("@atep/core: call `await init()` first");
}
// ---------------------------------------------------------------------------
// Helpers
export function hexToBytes(hex) {
    if (hex.length % 2 !== 0 || /[^0-9a-fA-F]/.test(hex))
        throw new Error("invalid hex");
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++)
        out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return out;
}
export function bytesToHex(b) {
    let s = "";
    for (const x of b)
        s += x.toString(16).padStart(2, "0");
    return s;
}
const hx = (v) => (typeof v === "string" ? v : bytesToHex(v));
const nowSecs = () => Math.floor(Date.now() / 1000);
function normalizePolicy(p) {
    const o = { ...p };
    for (const k of ["known_bundles", "seen_nonces", "attestations", "srls"]) {
        const v = p[k];
        if (v !== undefined)
            o[k] = v.map(hx);
    }
    if (p.detached_payload_hex !== undefined)
        o.detached_payload_hex = hx(p.detached_payload_hex);
    return JSON.stringify(o);
}
function signJson(o) {
    const j = {
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
/**
 * An agent identity. Its secret seeds live in wasm linear memory and are
 * zeroized when the object is freed. Call `free()` (or use `using`) when done.
 */
export class Identity {
    #raw;
    constructor(raw) {
        this.#raw = raw;
    }
    /** Generate a new identity. `encryption` adds X25519 and ML-KEM-768 keys (needed to receive encrypted envelopes). */
    static generate(encryption = true) {
        need();
        return new Identity(RawIdentity.generate(encryption));
    }
    /** From raw seeds (the same values the test vectors list). */
    static fromSeeds(seeds) {
        need();
        return new Identity(RawIdentity.fromSeeds(seeds.ed25519, seeds.mldsa65, seeds.x25519 ?? null, seeds.mlkem768 ?? null));
    }
    /** From seeds given as hex (the format of the vector `inputs`). */
    static fromSeedsHex(s) {
        return Identity.fromSeeds({
            ed25519: hexToBytes(s.ed25519),
            mldsa65: hexToBytes(s.mldsa65),
            x25519: s.x25519 ? hexToBytes(s.x25519) : undefined,
            mlkem768: s.mlkem768 ? hexToBytes(s.mlkem768) : undefined,
        });
    }
    /** From the CBOR secret key file written by `exportSecret` or the Rust CLI. */
    static fromSecret(secret) {
        need();
        return new Identity(RawIdentity.fromSecret(secret));
    }
    /** The secret key file. The returned array holds secrets: `fill(0)` it when done. */
    exportSecret() {
        return this.#raw.exportSecret();
    }
    /** Agent ID, `atep:...`. */
    get agentId() {
        return this.#raw.agentId();
    }
    get agentIdBytes() {
        return this.#raw.agentIdBytes();
    }
    get did() {
        return this.#raw.did();
    }
    get publicBundle() {
        return this.#raw.publicBundle();
    }
    get hasEncryption() {
        return this.#raw.hasEncryption();
    }
    /** Sign a payload into a tag 98 envelope (Ed25519 plus ML-DSA-65). */
    sign(payload, options = {}) {
        return this.#raw.sign(payload, signJson(options));
    }
    /** Open a tag 96 envelope addressed to this identity. Returns the inner signed envelope, unverified. */
    decrypt(data) {
        return this.#raw.decrypt(data);
    }
    /** Issue an attestation (spec section 7) about `options.subject`. */
    issueAttestation(o) {
        return this.#raw.issueAttestation(JSON.stringify({
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
        }));
    }
    /** Create a signed revocation list with this identity as issuer (spec section 8). */
    createSrl(o) {
        return this.#raw.createSrl(JSON.stringify({
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
        }));
    }
    /** Sign a log checkpoint with this identity as the log. */
    createCheckpoint(o) {
        return this.#raw.createCheckpoint(JSON.stringify({
            tree_size: o.treeSize,
            root_hash_hex: bytesToHex(o.rootHash),
            timestamp: o.timestamp,
            nonce_hex: o.nonce && bytesToHex(o.nonce),
            mode: o.deterministic ? "deterministic" : "hedged",
        }));
    }
    /** Verify with this identity as the recipient (opens tag 96 envelopes). */
    verify(data, policy = {}, now = nowSecs()) {
        return JSON.parse(rawVerifyAs(this.#raw, data, normalizePolicy(policy), now));
    }
    /** Zeroize and release the secret seeds. */
    free() {
        this.#raw.free();
    }
    [Symbol.dispose]() {
        this.#raw.free();
    }
}
// ---------------------------------------------------------------------------
// Functions
/** Generate an identity (alias of `Identity.generate`). */
export function keygen(encryption = true) {
    return Identity.generate(encryption);
}
/** Agent ID of a public bundle (or of an Identity). */
export function agentId(bundleOrIdentity) {
    need();
    return bundleOrIdentity instanceof Identity
        ? bundleOrIdentity.agentId
        : agentIdOfBundle(bundleOrIdentity);
}
/** Parse an Agent ID in `atep:` or `did:atep:` form. */
export function parseAgentId(s) {
    need();
    return JSON.parse(rawParseAgentId(s));
}
export function sign(identity, payload, options = {}) {
    return identity.sign(payload, options);
}
/** Encrypt a signed envelope to a recipient's public bundle (hybrid X25519 + ML-KEM-768, AES-256-GCM). */
export function encrypt(signedEnvelope, recipientBundle) {
    need();
    return rawEncrypt(signedEnvelope, recipientBundle);
}
/** Encrypt with explicit randomness. Only for reproducing test vectors. */
export function encryptDeterministic(signedEnvelope, recipientBundle, rnd) {
    need();
    return encryptWithRandomness(signedEnvelope, recipientBundle, rnd.x25519Ephemeral, rnd.mlkemM, rnd.iv);
}
export function decrypt(identity, data) {
    return identity.decrypt(data);
}
/**
 * Verify an envelope, spec section 10 steps 1 to 10. A rejection is returned
 * as `{ok: false, step, error}`, not thrown. Malformed arguments throw.
 */
export function verify(data, policy = {}, options = {}) {
    need();
    const now = options.now ?? nowSecs();
    if (options.recipient)
        return options.recipient.verify(data, policy, now);
    return JSON.parse(rawVerify(data, normalizePolicy(policy), now));
}
/** JSON debug rendering of any ATEP CBOR object (envelope, bundle, ...). Not canonical. */
export function view(data) {
    need();
    return JSON.parse(rawView(data));
}
export function sha256(data) {
    need();
    return rawSha256(data);
}
/** Put inline attestations into the (unsigned) unprotected header of an envelope. */
export function withAttestations(envelope, attestations) {
    need();
    return rawWithAttestations(envelope, JSON.stringify(attestations.map(bytesToHex)));
}
/** Attach a log inclusion proof to an attestation. */
export function withInclusionProof(attestation, proof) {
    need();
    return rawWithInclusionProof(attestation, proof.leafIndex, JSON.stringify(proof.auditPath.map(bytesToHex)), proof.checkpoint);
}
/** The attestation as submitted to a log: its inclusion proof header removed. This is the Merkle leaf. */
export function submittedFormOf(attestation) {
    need();
    return submittedForm(attestation);
}
/** RFC 9162 Merkle root over leaves. */
export function merkleRoot(leaves) {
    need();
    return hexToBytes(rawMerkleRoot(JSON.stringify(leaves.map(bytesToHex))));
}
/** RFC 9162 audit path of leaf `index`. */
export function auditPath(index, leaves) {
    need();
    return JSON.parse(rawAuditPath(index, JSON.stringify(leaves.map(bytesToHex)))).map(hexToBytes);
}
/** Verify a checkpoint envelope: steps 1 to 8, content type, trusted log, schema. */
export function verifyCheckpoint(cbor, trustedLogs, now = nowSecs()) {
    need();
    return JSON.parse(rawVerifyCheckpoint(cbor, JSON.stringify(trustedLogs), now));
}
/** Verify the inclusion proof an attestation carries (offline, against trusted logs). */
export function verifyInclusion(attestation, trustedLogs, now = nowSecs()) {
    need();
    return JSON.parse(rawVerifyInclusion(attestation, JSON.stringify(trustedLogs), now));
}
/** Check a consistency proof document `{old, new, proof}` (CBOR). */
export function checkConsistency(cbor, trustedLogs, now = nowSecs()) {
    need();
    return JSON.parse(rawCheckConsistency(cbor, JSON.stringify(trustedLogs), now));
}
/** Check a split view document `{a, b, proof?}` (CBOR). */
export function checkSplitView(cbor, trustedLogs, now = nowSecs()) {
    need();
    return JSON.parse(rawCheckSplitView(cbor, JSON.stringify(trustedLogs), now));
}
function normalizeSrlContext(c) {
    const o = { ...c };
    for (const k of ["known_bundles", "attestations"]) {
        const v = c[k];
        if (v !== undefined)
            o[k] = v.map(hx);
    }
    return JSON.stringify(o);
}
/**
 * Verify a signed revocation list and apply the freshness rule. `cached` is a
 * previously accepted SRL of the same issuer (rollback and conflict rules apply).
 */
export function verifySrl(srl, options = {}) {
    need();
    return JSON.parse(rawVerifySrl(srl, options.now ?? nowSecs(), JSON.stringify({ on_stale: options.onStale ?? "fail-closed" }), options.cached ?? undefined, options.context ? normalizeSrlContext(options.context) : undefined));
}
/** Is `id` a valid `chain-id`: one of the five registered ids, or `x-` plus a lowercase name. Pure function. */
export function chainIdKind(id) {
    need();
    return JSON.parse(rawChainIdKind(id));
}
/** Decode an anchor record payload (strict deterministic CBOR). Invalid input is a result, not an exception. */
export function parseAnchorRecord(payload) {
    need();
    return JSON.parse(rawParseAnchorRecord(payload));
}
/** Deterministic CBOR of an anchor record (no `block-height` key when it is null or absent). */
export function encodeAnchorRecord(record) {
    need();
    return rawEncodeAnchorRecord(JSON.stringify(record));
}
/** Verify a checkpoint envelope (as `verifyCheckpoint`) and add `checkpoint_hash`: SHA-256 of the verified payload. */
export function checkpointHash(cbor, trustedLogs, now = nowSecs()) {
    need();
    return JSON.parse(rawCheckpointHash(cbor, JSON.stringify(trustedLogs), now));
}
/**
 * Take a log-signed anchor envelope as published: steps 1 to 8 (reported as they are), then the content
 * type, the record schema, the signer (`log`) and the checkpoint hash (hex), in that order.
 * Whether the witness really holds the hash is not checked.
 */
export function checkPublishedAnchor(envelope, log, checkpointHashHex, now = nowSecs()) {
    need();
    return JSON.parse(rawCheckPublishedAnchor(envelope, log, checkpointHashHex, now));
}
/** Parse the `require_anchor` rules of a trust policy object. A bad policy is `{ok: false, error: "policy_invalid"}`. */
export function parseRequireAnchor(policy) {
    need();
    return JSON.parse(rawParseRequireAnchor(JSON.stringify(policy)));
}
/**
 * The admission rules of a log (spec section 9) applied to one submission, including the data rules of
 * `registry-endpoint` and `domain-control`. `logged` are documents admitted first, in order (hex or bytes).
 * This package has no log: this is a pure check of the rules.
 */
export function checkAdmission(submission, options) {
    need();
    return JSON.parse(rawCheckAdmission(submission, JSON.stringify({
        now: options.now ?? nowSecs(),
        log: options.log,
        max_envelope_bytes: options.maxEnvelopeBytes ?? 65536,
        logged: (options.logged ?? []).map(hx),
    })));
}
/** Run the domain binding check (section 7) over a fixture of fetcher answers. No network is used. */
export function checkDomainBinding(fixture) {
    need();
    return JSON.parse(rawCheckDomainBinding(JSON.stringify(fixture)));
}
