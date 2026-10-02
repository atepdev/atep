/* @ts-self-types="./atep_wasm.d.ts" */

/**
 * An agent identity. The secret seeds stay inside wasm memory.
 */
export class Identity {
    static __wrap(ptr) {
        const obj = Object.create(Identity.prototype);
        obj.__wbg_ptr = ptr;
        IdentityFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        IdentityFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_identity_free(ptr, 0);
    }
    /**
     * @returns {Uint8Array}
     */
    agentIdBytes() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.identity_agentIdBytes(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var v1 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export3(r0, r1 * 1, 1);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Agent ID in text form (`atep:...`).
     * @returns {string}
     */
    agentId() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.identity_agentId(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export3(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Sign a log checkpoint (this identity is the log). `options` JSON:
     * `{tree_size, root_hash_hex, timestamp, nonce_hex?, mode?}`.
     * @param {string} options
     * @returns {Uint8Array}
     */
    createCheckpoint(options) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(options, wasm.__wbindgen_export2, wasm.__wbindgen_export4);
            const len0 = WASM_VECTOR_LEN;
            wasm.identity_createCheckpoint(retptr, this.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v2 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export3(r0, r1 * 1, 1);
            return v2;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Create a signed revocation list (spec section 8). `options` JSON:
     * `{sequence, issued_at, next_update, revoked: [{id_hex (16 bytes, an
     * attestation) | id (an Agent ID), reason, revoked_at}], nonce_hex?,
     * mode?, include_bundle?}`. The issuer is this identity.
     * @param {string} options
     * @returns {Uint8Array}
     */
    createSrl(options) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(options, wasm.__wbindgen_export2, wasm.__wbindgen_export4);
            const len0 = WASM_VECTOR_LEN;
            wasm.identity_createSrl(retptr, this.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v2 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export3(r0, r1 * 1, 1);
            return v2;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Open a tag 96 envelope addressed to this identity; returns the inner
     * tag 98 envelope (not verified, run `verify` on it or use `verify`
     * directly with this identity as recipient).
     * @param {Uint8Array} data
     * @returns {Uint8Array}
     */
    decrypt(data) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            wasm.identity_decrypt(retptr, this.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v2 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export3(r0, r1 * 1, 1);
            return v2;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @returns {string}
     */
    did() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.identity_did(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export3(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * The CBOR secret key file. This copies secret material into a JS
     * Uint8Array: the caller owns it and should `.fill(0)` it after use.
     * @returns {Uint8Array}
     */
    exportSecret() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.identity_exportSecret(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var v1 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export3(r0, r1 * 1, 1);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * From the CBOR secret key file written by `exportSecret` (and by the Rust CLI).
     * @param {Uint8Array} secret_file
     * @returns {Identity}
     */
    static fromSecret(secret_file) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(secret_file, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            wasm.identity_fromSecret(retptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return Identity.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * From raw seeds. `x25519` and `mlkem768` are both given or both empty.
     * @param {Uint8Array} ed25519
     * @param {Uint8Array} mldsa65
     * @param {Uint8Array | null} [x25519]
     * @param {Uint8Array | null} [mlkem768]
     * @returns {Identity}
     */
    static fromSeeds(ed25519, mldsa65, x25519, mlkem768) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(ed25519, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArray8ToWasm0(mldsa65, wasm.__wbindgen_export2);
            const len1 = WASM_VECTOR_LEN;
            var ptr2 = isLikeNone(x25519) ? 0 : passArray8ToWasm0(x25519, wasm.__wbindgen_export2);
            var len2 = WASM_VECTOR_LEN;
            var ptr3 = isLikeNone(mlkem768) ? 0 : passArray8ToWasm0(mlkem768, wasm.__wbindgen_export2);
            var len3 = WASM_VECTOR_LEN;
            wasm.identity_fromSeeds(retptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return Identity.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * New identity from system randomness (`crypto.getRandomValues`).
     * @param {boolean} with_encryption
     * @returns {Identity}
     */
    static generate(with_encryption) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.identity_generate(retptr, with_encryption);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return Identity.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @returns {boolean}
     */
    hasEncryption() {
        const ret = wasm.identity_hasEncryption(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * Issue an attestation (spec section 7). `options` is JSON:
     * `{subject, claim, issued_at, expires_at, data?: JSON object (or data_hex: CBOR),
     * evidence_hex?, evidence_uri?, id_hex?, nonce_hex?, mode?, include_bundle?,
     * allow_long_default?}`. In `data`, `{"$hex": "..."}` becomes a byte string.
     * @param {string} options
     * @returns {Uint8Array}
     */
    issueAttestation(options) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(options, wasm.__wbindgen_export2, wasm.__wbindgen_export4);
            const len0 = WASM_VECTOR_LEN;
            wasm.identity_issueAttestation(retptr, this.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v2 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export3(r0, r1 * 1, 1);
            return v2;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Canonical public key bundle (CBOR).
     * @returns {Uint8Array}
     */
    publicBundle() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.identity_publicBundle(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var v1 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export3(r0, r1 * 1, 1);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Sign a payload into a tag 98 envelope. `options` is JSON:
     * `{content_type?, issued_at, expires_at?, detached?, include_bundle?,
     * nonce_hex?, mode?: "hedged"|"deterministic", command_class?}`.
     * @param {Uint8Array} payload
     * @param {string} options
     * @returns {Uint8Array}
     */
    sign(payload, options) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(payload, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(options, wasm.__wbindgen_export2, wasm.__wbindgen_export4);
            const len1 = WASM_VECTOR_LEN;
            wasm.identity_sign(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v3 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export3(r0, r1 * 1, 1);
            return v3;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
}
if (Symbol.dispose) Identity.prototype[Symbol.dispose] = Identity.prototype.free;

/**
 * Agent ID (text form) of a public bundle.
 * @param {Uint8Array} bundle_bytes
 * @returns {string}
 */
export function agentIdOfBundle(bundle_bytes) {
    let deferred3_0;
    let deferred3_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(bundle_bytes, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        wasm.agentIdOfBundle(retptr, ptr0, len0);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr2 = r0;
        var len2 = r1;
        if (r3) {
            ptr2 = 0; len2 = 0;
            throw takeObject(r2);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export3(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Audit path for `index` (JSON array of hex hashes) over the leaves.
 * @param {number} index
 * @param {string} leaves
 * @returns {string}
 */
export function auditPath(index, leaves) {
    let deferred3_0;
    let deferred3_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(leaves, wasm.__wbindgen_export2, wasm.__wbindgen_export4);
        const len0 = WASM_VECTOR_LEN;
        wasm.auditPath(retptr, index, ptr0, len0);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr2 = r0;
        var len2 = r1;
        if (r3) {
            ptr2 = 0; len2 = 0;
            throw takeObject(r2);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export3(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Check a `chain-id` (spec section 9, "The `chain-id` registry"): returns
 * `{ok: true, kind: "registered" | "extension"}` or `{ok: false}`.
 * @param {string} id
 * @returns {string}
 */
export function chainIdKind(id) {
    let deferred2_0;
    let deferred2_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(id, wasm.__wbindgen_export2, wasm.__wbindgen_export4);
        const len0 = WASM_VECTOR_LEN;
        wasm.chainIdKind(retptr, ptr0, len0);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        deferred2_0 = r0;
        deferred2_1 = r1;
        return getStringFromWasm0(r0, r1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export3(deferred2_0, deferred2_1, 1);
    }
}

/**
 * Run the admission rules of a log (spec section 9, "Admission", the 14 core
 * claim types, `registry-endpoint` and `domain-control` data rules) on a
 * submission. `options` JSON: `{now, log, max_envelope_bytes, logged?: [hex]}`
 * where `logged` are documents admitted first, in order. Returns
 * `{ok: true, document}` or `{ok: false, refusal, step?, error?}`.
 * @param {Uint8Array} cbor
 * @param {string} options
 * @returns {string}
 */
export function checkAdmission(cbor, options) {
    let deferred4_0;
    let deferred4_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(cbor, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(options, wasm.__wbindgen_export2, wasm.__wbindgen_export4);
        const len1 = WASM_VECTOR_LEN;
        wasm.checkAdmission(retptr, ptr0, len0, ptr1, len1);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr3 = r0;
        var len3 = r1;
        if (r3) {
            ptr3 = 0; len3 = 0;
            throw takeObject(r2);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export3(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Check a consistency proof document `{old, new, proof}` (CBOR).
 * @param {Uint8Array} cbor
 * @param {string} trusted_logs
 * @param {number} now
 * @returns {string}
 */
export function checkConsistency(cbor, trusted_logs, now) {
    let deferred4_0;
    let deferred4_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(cbor, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(trusted_logs, wasm.__wbindgen_export2, wasm.__wbindgen_export4);
        const len1 = WASM_VECTOR_LEN;
        wasm.checkConsistency(retptr, ptr0, len0, ptr1, len1, now);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr3 = r0;
        var len3 = r1;
        if (r3) {
            ptr3 = 0; len3 = 0;
            throw takeObject(r2);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export3(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Run the domain binding check (spec section 7, "Checking a domain binding")
 * on a fixture: `{domain, agent_id, options: {require_both, require_dnssec},
 * well_known: {host: answer}, txt: {name: answer}}`, the fetcher's answers
 * by name (a name with no key does not exist). No network is used. Returns
 * `{well_known, dns, outcome, queried: {well_known, txt}}`.
 * @param {string} fixture
 * @returns {string}
 */
export function checkDomainBinding(fixture) {
    let deferred3_0;
    let deferred3_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(fixture, wasm.__wbindgen_export2, wasm.__wbindgen_export4);
        const len0 = WASM_VECTOR_LEN;
        wasm.checkDomainBinding(retptr, ptr0, len0);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr2 = r0;
        var len2 = r1;
        if (r3) {
            ptr2 = 0; len2 = 0;
            throw takeObject(r2);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export3(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Take a log-signed anchor envelope as published (spec section 9, "Anchor
 * records"): steps 1 to 8, content type, record schema, signer is `log`,
 * record is for `checkpoint_hash_hex`. Returns `{ok: true, log, record}` or
 * `{ok: false, step, error}`.
 * @param {Uint8Array} cbor
 * @param {string} log_id
 * @param {string} checkpoint_hash_hex
 * @param {number} now
 * @returns {string}
 */
export function checkPublishedAnchor(cbor, log_id, checkpoint_hash_hex, now) {
    let deferred5_0;
    let deferred5_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(cbor, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(log_id, wasm.__wbindgen_export2, wasm.__wbindgen_export4);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(checkpoint_hash_hex, wasm.__wbindgen_export2, wasm.__wbindgen_export4);
        const len2 = WASM_VECTOR_LEN;
        wasm.checkPublishedAnchor(retptr, ptr0, len0, ptr1, len1, ptr2, len2, now);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr4 = r0;
        var len4 = r1;
        if (r3) {
            ptr4 = 0; len4 = 0;
            throw takeObject(r2);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export3(deferred5_0, deferred5_1, 1);
    }
}

/**
 * Check a split view document `{a, b, proof?}` (CBOR).
 * @param {Uint8Array} cbor
 * @param {string} trusted_logs
 * @param {number} now
 * @returns {string}
 */
export function checkSplitView(cbor, trusted_logs, now) {
    let deferred4_0;
    let deferred4_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(cbor, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(trusted_logs, wasm.__wbindgen_export2, wasm.__wbindgen_export4);
        const len1 = WASM_VECTOR_LEN;
        wasm.checkSplitView(retptr, ptr0, len0, ptr1, len1, now);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr3 = r0;
        var len3 = r1;
        if (r3) {
            ptr3 = 0; len3 = 0;
            throw takeObject(r2);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export3(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Verify a checkpoint envelope (as `verifyCheckpoint`) and add its checkpoint
 * hash, SHA-256 of the verified payload bytes. Returns
 * `{ok: true, checkpoint, checkpoint_hash, payload_hex}` or a rejection.
 * @param {Uint8Array} cbor
 * @param {string} trusted_logs
 * @param {number} now
 * @returns {string}
 */
export function checkpointHash(cbor, trusted_logs, now) {
    let deferred4_0;
    let deferred4_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(cbor, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(trusted_logs, wasm.__wbindgen_export2, wasm.__wbindgen_export4);
        const len1 = WASM_VECTOR_LEN;
        wasm.checkpointHash(retptr, ptr0, len0, ptr1, len1, now);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr3 = r0;
        var len3 = r1;
        if (r3) {
            ptr3 = 0; len3 = 0;
            throw takeObject(r2);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export3(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Encode an anchor record (deterministic CBOR). `record` is JSON
 * `{checkpoint_hash, chain_id, transaction_id, block_height?, anchored_at}`
 * (the shape `parseAnchorRecord` returns). Throws when the chain id is invalid.
 * @param {string} record
 * @returns {Uint8Array}
 */
export function encodeAnchorRecord(record) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(record, wasm.__wbindgen_export2, wasm.__wbindgen_export4);
        const len0 = WASM_VECTOR_LEN;
        wasm.encodeAnchorRecord(retptr, ptr0, len0);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        if (r3) {
            throw takeObject(r2);
        }
        var v2 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_export3(r0, r1 * 1, 1);
        return v2;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Encrypt a signed envelope to a recipient bundle with fresh randomness.
 * @param {Uint8Array} signed_envelope
 * @param {Uint8Array} recipient_bundle
 * @returns {Uint8Array}
 */
export function encrypt(signed_envelope, recipient_bundle) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(signed_envelope, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(recipient_bundle, wasm.__wbindgen_export2);
        const len1 = WASM_VECTOR_LEN;
        wasm.encrypt(retptr, ptr0, len0, ptr1, len1);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        if (r3) {
            throw takeObject(r2);
        }
        var v3 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_export3(r0, r1 * 1, 1);
        return v3;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Encrypt with caller supplied randomness (for reproducing test vectors; do
 * not use in production). Sizes: 32, 32 and 12 bytes.
 * @param {Uint8Array} signed_envelope
 * @param {Uint8Array} recipient_bundle
 * @param {Uint8Array} x25519_ephemeral
 * @param {Uint8Array} mlkem_m
 * @param {Uint8Array} iv
 * @returns {Uint8Array}
 */
export function encryptWithRandomness(signed_envelope, recipient_bundle, x25519_ephemeral, mlkem_m, iv) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(signed_envelope, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(recipient_bundle, wasm.__wbindgen_export2);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(x25519_ephemeral, wasm.__wbindgen_export2);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArray8ToWasm0(mlkem_m, wasm.__wbindgen_export2);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passArray8ToWasm0(iv, wasm.__wbindgen_export2);
        const len4 = WASM_VECTOR_LEN;
        wasm.encryptWithRandomness(retptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        if (r3) {
            throw takeObject(r2);
        }
        var v6 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_export3(r0, r1 * 1, 1);
        return v6;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * RFC 9162 Merkle tree root over leaves given as a JSON array of hex strings.
 * @param {string} leaves
 * @returns {string}
 */
export function merkleRoot(leaves) {
    let deferred3_0;
    let deferred3_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(leaves, wasm.__wbindgen_export2, wasm.__wbindgen_export4);
        const len0 = WASM_VECTOR_LEN;
        wasm.merkleRoot(retptr, ptr0, len0);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr2 = r0;
        var len2 = r1;
        if (r3) {
            ptr2 = 0; len2 = 0;
            throw takeObject(r2);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export3(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Parse any accepted Agent ID spelling (`atep:` text or `did:atep:`) and
 * return `{text, did, hex}` as JSON.
 * @param {string} s
 * @returns {string}
 */
export function parseAgentId(s) {
    let deferred3_0;
    let deferred3_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(s, wasm.__wbindgen_export2, wasm.__wbindgen_export4);
        const len0 = WASM_VECTOR_LEN;
        wasm.parseAgentId(retptr, ptr0, len0);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr2 = r0;
        var len2 = r1;
        if (r3) {
            ptr2 = 0; len2 = 0;
            throw takeObject(r2);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export3(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Decode an anchor record payload (strict deterministic CBOR, schema of
 * section 9). Returns `{ok: true, record}` or
 * `{ok: false, error: "anchor_record_invalid"}`. An accepted record must
 * re-encode to the same bytes, else this throws (an internal inconsistency).
 * @param {Uint8Array} payload
 * @returns {string}
 */
export function parseAnchorRecord(payload) {
    let deferred3_0;
    let deferred3_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(payload, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        wasm.parseAnchorRecord(retptr, ptr0, len0);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr2 = r0;
        var len2 = r1;
        if (r3) {
            ptr2 = 0; len2 = 0;
            throw takeObject(r2);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export3(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Parse the `require_anchor` rules of a trust policy (a JSON object, the
 * policy file format). Returns `{ok: true, require_anchor: [...]}` or
 * `{ok: false, error: "policy_invalid"}` (a configuration error, no step).
 * @param {string} policy
 * @returns {string}
 */
export function parseRequireAnchor(policy) {
    let deferred3_0;
    let deferred3_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(policy, wasm.__wbindgen_export2, wasm.__wbindgen_export4);
        const len0 = WASM_VECTOR_LEN;
        wasm.parseRequireAnchor(retptr, ptr0, len0);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr2 = r0;
        var len2 = r1;
        if (r3) {
            ptr2 = 0; len2 = 0;
            throw takeObject(r2);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export3(deferred3_0, deferred3_1, 1);
    }
}

/**
 * SHA-256.
 * @param {Uint8Array} data
 * @returns {Uint8Array}
 */
export function sha256(data) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        wasm.sha256(retptr, ptr0, len0);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var v2 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_export3(r0, r1 * 1, 1);
        return v2;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * The form of an attestation that is submitted to a log (the `-70012` header removed).
 * @param {Uint8Array} envelope_bytes
 * @returns {Uint8Array}
 */
export function submittedForm(envelope_bytes) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(envelope_bytes, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        wasm.submittedForm(retptr, ptr0, len0);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        if (r3) {
            throw takeObject(r2);
        }
        var v2 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_export3(r0, r1 * 1, 1);
        return v2;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Verify an envelope (spec section 10, all ten steps). `policy` is JSON in the
 * format of the test vectors: `{max_skew_secs?, known_bundles: [hex],
 * seen_nonces: [hex], revocations: [{id, reason, revoked_at}],
 * detached_payload_hex?, trust?: {...policy file...}, attestations?: [hex],
 * srls?: [hex], recipient_seeds?: {...}}`. A recipient `Identity` object can
 * be passed instead of `recipient_seeds` (preferred: the seeds then never
 * enter JSON). Returns JSON: `{ok: true, signer, ..., payload_hex}` or
 * `{ok: false, step, error, cause?}`.
 * @param {Uint8Array} data
 * @param {string} policy
 * @param {number} now
 * @returns {string}
 */
export function verify(data, policy, now) {
    let deferred4_0;
    let deferred4_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(policy, wasm.__wbindgen_export2, wasm.__wbindgen_export4);
        const len1 = WASM_VECTOR_LEN;
        wasm.verify(retptr, ptr0, len0, ptr1, len1, now);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr3 = r0;
        var len3 = r1;
        if (r3) {
            ptr3 = 0; len3 = 0;
            throw takeObject(r2);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export3(deferred4_0, deferred4_1, 1);
    }
}

/**
 * `verify` with a recipient `Identity` object that opens tag 96 envelopes.
 * @param {Identity} recipient
 * @param {Uint8Array} data
 * @param {string} policy
 * @param {number} now
 * @returns {string}
 */
export function verifyAs(recipient, data, policy, now) {
    let deferred4_0;
    let deferred4_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        _assertClass(recipient, Identity);
        const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(policy, wasm.__wbindgen_export2, wasm.__wbindgen_export4);
        const len1 = WASM_VECTOR_LEN;
        wasm.verifyAs(retptr, recipient.__wbg_ptr, ptr0, len0, ptr1, len1, now);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr3 = r0;
        var len3 = r1;
        if (r3) {
            ptr3 = 0; len3 = 0;
            throw takeObject(r2);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export3(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Verify a checkpoint envelope against trusted logs (JSON array of Agent IDs).
 * @param {Uint8Array} cbor
 * @param {string} trusted_logs
 * @param {number} now
 * @returns {string}
 */
export function verifyCheckpoint(cbor, trusted_logs, now) {
    let deferred4_0;
    let deferred4_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(cbor, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(trusted_logs, wasm.__wbindgen_export2, wasm.__wbindgen_export4);
        const len1 = WASM_VECTOR_LEN;
        wasm.verifyCheckpoint(retptr, ptr0, len0, ptr1, len1, now);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr3 = r0;
        var len3 = r1;
        if (r3) {
            ptr3 = 0; len3 = 0;
            throw takeObject(r2);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export3(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Verify the inclusion proof carried by an attestation.
 * @param {Uint8Array} attestation_bytes
 * @param {string} trusted_logs
 * @param {number} now
 * @returns {string}
 */
export function verifyInclusion(attestation_bytes, trusted_logs, now) {
    let deferred4_0;
    let deferred4_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(attestation_bytes, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(trusted_logs, wasm.__wbindgen_export2, wasm.__wbindgen_export4);
        const len1 = WASM_VECTOR_LEN;
        wasm.verifyInclusion(retptr, ptr0, len0, ptr1, len1, now);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr3 = r0;
        var len3 = r1;
        if (r3) {
            ptr3 = 0; len3 = 0;
            throw takeObject(r2);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export3(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Verify an SRL envelope and apply the freshness policy. `srl_policy` JSON:
 * `{on_stale: "fail-closed"|"fail-open", on_missing?}`; `cached_srl` is an
 * optional previously accepted SRL envelope (rollback rules apply).
 * `context` is optional JSON `{known_bundles?: [hex], attestations?: [hex],
 * revocations?: [{id, reason, revoked_at}], max_skew_secs?}`: the verifier's
 * own context in which the cached list and the list are loaded (steps 1 to 8,
 * spec section 8). Without it only the inline bundles are known.
 * @param {Uint8Array} cbor
 * @param {number} now
 * @param {string} srl_policy
 * @param {Uint8Array | null} [cached_srl]
 * @param {string | null} [context]
 * @returns {string}
 */
export function verifySrl(cbor, now, srl_policy, cached_srl, context) {
    let deferred6_0;
    let deferred6_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(cbor, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(srl_policy, wasm.__wbindgen_export2, wasm.__wbindgen_export4);
        const len1 = WASM_VECTOR_LEN;
        var ptr2 = isLikeNone(cached_srl) ? 0 : passArray8ToWasm0(cached_srl, wasm.__wbindgen_export2);
        var len2 = WASM_VECTOR_LEN;
        var ptr3 = isLikeNone(context) ? 0 : passStringToWasm0(context, wasm.__wbindgen_export2, wasm.__wbindgen_export4);
        var len3 = WASM_VECTOR_LEN;
        wasm.verifySrl(retptr, ptr0, len0, now, ptr1, len1, ptr2, len2, ptr3, len3);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr5 = r0;
        var len5 = r1;
        if (r3) {
            ptr5 = 0; len5 = 0;
            throw takeObject(r2);
        }
        deferred6_0 = ptr5;
        deferred6_1 = len5;
        return getStringFromWasm0(ptr5, len5);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export3(deferred6_0, deferred6_1, 1);
    }
}

/**
 * JSON debug view of any ATEP CBOR object.
 * @param {Uint8Array} data
 * @returns {string}
 */
export function view(data) {
    let deferred3_0;
    let deferred3_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        wasm.view(retptr, ptr0, len0);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr2 = r0;
        var len2 = r1;
        if (r3) {
            ptr2 = 0; len2 = 0;
            throw takeObject(r2);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export3(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Put inline attestations (`-70009`) into the unprotected header of an
 * envelope. `attestations` is a JSON array of hex strings.
 * @param {Uint8Array} envelope_bytes
 * @param {string} attestations
 * @returns {Uint8Array}
 */
export function withAttestations(envelope_bytes, attestations) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(envelope_bytes, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(attestations, wasm.__wbindgen_export2, wasm.__wbindgen_export4);
        const len1 = WASM_VECTOR_LEN;
        wasm.withAttestations(retptr, ptr0, len0, ptr1, len1);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        if (r3) {
            throw takeObject(r2);
        }
        var v3 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_export3(r0, r1 * 1, 1);
        return v3;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Attach an inclusion proof (`-70012`) to an attestation. `audit_path` is a
 * JSON array of 32 byte hex hashes, `checkpoint` the signed checkpoint envelope.
 * @param {Uint8Array} attestation_bytes
 * @param {number} leaf_index
 * @param {string} audit_path
 * @param {Uint8Array} checkpoint
 * @returns {Uint8Array}
 */
export function withInclusionProof(attestation_bytes, leaf_index, audit_path, checkpoint) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(attestation_bytes, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(audit_path, wasm.__wbindgen_export2, wasm.__wbindgen_export4);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(checkpoint, wasm.__wbindgen_export2);
        const len2 = WASM_VECTOR_LEN;
        wasm.withInclusionProof(retptr, ptr0, len0, leaf_index, ptr1, len1, ptr2, len2);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        if (r3) {
            throw takeObject(r2);
        }
        var v4 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_export3(r0, r1 * 1, 1);
        return v4;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}
function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg_Error_30c8987f7c2ed4e2: function(arg0, arg1) {
            const ret = Error(getStringFromWasm0(arg0, arg1));
            return addHeapObject(ret);
        },
        __wbg___wbindgen_throw_41e9ee4f547fc59a: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg_getRandomValues_436a51d0629d84e1: function() { return handleError(function (arg0, arg1) {
            globalThis.crypto.getRandomValues(getArrayU8FromWasm0(arg0, arg1));
        }, arguments); },
        __wbindgen_object_drop_ref: function(arg0) {
            takeObject(arg0);
        },
    };
    return {
        __proto__: null,
        "./atep_wasm_bg.js": import0,
    };
}

const IdentityFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_identity_free(ptr, 1));

function addHeapObject(obj) {
    if (heap_next === heap.length) heap.push(heap.length + 1);
    const idx = heap_next;
    heap_next = heap[idx];

    heap[idx] = obj;
    return idx;
}

function _assertClass(instance, klass) {
    if (!(instance instanceof klass)) {
        throw new Error(`expected instance of ${klass.name}`);
    }
}

function dropObject(idx) {
    if (idx < 1028) return;
    heap[idx] = heap_next;
    heap_next = idx;
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

let cachedDataViewMemory0 = null;
function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function getStringFromWasm0(ptr, len) {
    return decodeText(ptr >>> 0, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function getObject(idx) { return heap[idx]; }

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        wasm.__wbindgen_export(addHeapObject(e));
    }
}

let heap = new Array(1024).fill(undefined);
heap.push(undefined, null, true, false);

let heap_next = heap.length;

function isLikeNone(x) {
    return x === undefined || x === null;
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

function takeObject(idx) {
    const ret = getObject(idx);
    dropObject(idx);
    return ret;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;

let wasmModule, wasmInstance, wasm;
function __wbg_finalize_init(instance, module) {
    wasmInstance = instance;
    wasm = instance.exports;
    wasmModule = module;
    cachedDataViewMemory0 = null;
    cachedUint8ArrayMemory0 = null;
    return wasm;
}

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (!module.ok) {
            throw new Error(`failed to fetch Wasm: ${module.status} ${module.statusText} fetching '${module.url}'`);
        }

        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);
            } catch (e) {
                const validResponse = expectedResponseType(module.type);

                if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else { throw e; }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);
    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };
        } else {
            return instance;
        }
    }

    function expectedResponseType(type) {
        switch (type) {
            case 'basic': case 'cors': case 'default': return true;
        }
        return false;
    }
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (module !== undefined) {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();
    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }
    const instance = new WebAssembly.Instance(module, imports);
    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (module_or_path !== undefined) {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (module_or_path === undefined) {
        module_or_path = new URL('atep_wasm_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync, __wbg_init as default };
