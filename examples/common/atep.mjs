// Shared ATEP helpers for the adapter examples. Transport free: every function
// here deals with envelope BYTES; the adapters only move those bytes.
import {
  init, keygen, Identity, encrypt, verify, withAttestations, agentId, sha256, bytesToHex, hexToBytes,
} from "@atep/core";

export { init, keygen, Identity, bytesToHex, hexToBytes };

export const te = new TextEncoder();
export const td = new TextDecoder();
export const nowSecs = () => Math.floor(Date.now() / 1000);

/** Envelope bytes <-> base64url text (no padding), the carriage used by MCP and A2A. */
export const b64u = (bytes) => Buffer.from(bytes).toString("base64url");
export function unb64u(text) {
  if (typeof text !== "string" || !/^[A-Za-z0-9_-]*$/.test(text)) throw new Error("not base64url");
  return new Uint8Array(Buffer.from(text, "base64url"));
}
export const sha256Hex = (bytes) => bytesToHex(sha256(bytes));

export const CLAIM = "operator-of";

/**
 * A local trust setup for the demos: one root, and any number of agents the
 * root attests to. In real use the root is an issuer you pin out of band.
 */
export function makeFixture(names = ["server", "client"]) {
  const root = keygen(false);
  const agents = {};
  const t = nowSecs();
  for (const name of names) {
    const id = keygen(true);
    const attestation = root.issueAttestation({
      subject: id.agentId, claim: CLAIM, issuedAt: t - 10, expiresAt: t + 86400, data: { operator: `${name}.example` },
    });
    agents[name] = { identity: id, attestation };
  }
  return { root, agents };
}

/** What a receiving agent needs to know about its trust anchor (all public). */
export const trustAnchor = (root) => ({ rootAgentId: root.agentId, rootBundleB64u: b64u(root.publicBundle) });

/** Serialisable configuration handed to a spawned agent process (contains its secret: demo only). */
export function agentConfig(root, agent, peer) {
  const secret = agent.identity.exportSecret();
  const cfg = {
    ...trustAnchor(root),
    secretB64u: b64u(secret),
    attestationB64u: b64u(agent.attestation),
    peerAgentId: peer?.identity.agentId,
  };
  secret.fill(0);
  return cfg;
}

export const identityFromConfig = (cfg) => Identity.fromSecret(unb64u(cfg.secretB64u));

/**
 * Sender side: sign `payload` (UTF-8 text), attach the sender's attestation,
 * then encrypt to the recipient (sign-then-encrypt, spec section 5).
 * Returns the envelope bytes and the nonce so the caller can correlate replies.
 */
export function seal({ sender, attestation, payload, recipientBundle, contentType = "application/json", ttl = 300, issuedAt }) {
  const t = issuedAt ?? nowSecs();
  const nonce = crypto.getRandomValues(new Uint8Array(16));
  let signed = sender.sign(te.encode(payload), { issuedAt: t, expiresAt: t + ttl, contentType, nonce });
  if (attestation) signed = withAttestations(signed, [attestation]);
  return { bytes: encrypt(signed, recipientBundle), nonceHex: bytesToHex(nonce) };
}

/**
 * Receiver side. Wraps `verify` (spec section 10, steps 1 to 10) with a trust
 * policy and a replay set. Returns {ok:true, ...} or {ok:false, step, error}.
 * The payload text is only released when ok is true.
 */
export class Verifier {
  constructor({ identity, rootAgentId, rootBundleB64u, requireClaim = CLAIM, seen = new Set() }) {
    this.identity = identity;
    this.policy = {
      trust: { roots: [rootAgentId], rules: [{ claim: requireClaim }] },
      known_bundles: [unb64u(rootBundleB64u)],
    };
    this.seen = seen;
  }

  check(envelopeBytes) {
    const r = verify(envelopeBytes, { ...this.policy, seen_nonces: [...this.seen] }, { recipient: this.identity, now: nowSecs() });
    if (!r.ok) return { ok: false, step: r.step, error: r.error, cause: r.cause };
    this.seen.add(r.nonce_hex); // only after every step passed
    return {
      ok: true,
      signer: r.signer,
      nonceHex: r.nonce_hex,
      claims: r.claims.map((c) => ({ claim: c.claim, issuer: c.issuer })),
      contentType: r.content_type,
      payloadBytes: hexToBytes(r.payload_hex),
    };
  }
}

export { agentId };
