// Transport independent client logic: build a request envelope, open a reply.
import { seal, Verifier, agentId, b64u, unb64u, td, bytesToHex } from "./atep.mjs";

export class AtepClient {
  /**
   * @param serverBundleB64u the server's public bundle (from the transport's identity
   *        discovery); it is accepted only if it hashes to `expectedServerId`, which the
   *        caller pinned out of band.
   */
  constructor({ identity, attestation, rootAgentId, rootBundleB64u, expectedServerId, serverBundleB64u }) {
    this.identity = identity;
    this.attestation = attestation;
    this.expectedServerId = expectedServerId;
    this.serverBundle = unb64u(serverBundleB64u);
    if (agentId(this.serverBundle) !== expectedServerId) throw new Error("server bundle does not match pinned Agent ID");
    this.verifier = new Verifier({ identity, rootAgentId, rootBundleB64u });
    this.bundleB64u = b64u(identity.publicBundle);
  }

  /** Returns {envelopeB64u, bytes, nonceHex, replyToBundleB64u}. */
  request(text, { attestation = this.attestation } = {}) {
    const payload = JSON.stringify({ kind: "note", text });
    const s = seal({ sender: this.identity, attestation, payload, recipientBundle: this.serverBundle });
    return { bytes: s.bytes, envelopeB64u: b64u(s.bytes), nonceHex: s.nonceHex, replyToBundleB64u: this.bundleB64u };
  }

  /** Verify a reply (full verifier, trust policy, replay set); returns the parsed reply data. */
  openReply(envelopeB64u, requestNonceHex) {
    const v = this.verifier.check(unb64u(envelopeB64u));
    if (!v.ok) throw new Error(`reply rejected at step ${v.step}: ${v.error}`);
    if (v.signer !== this.expectedServerId) throw new Error("reply signed by an unexpected agent");
    const reply = JSON.parse(td.decode(v.payloadBytes));
    if (reply.in_reply_to !== requestNonceHex) throw new Error("reply does not answer this request");
    return { reply, signer: v.signer, claims: v.claims, nonceHex: v.nonceHex };
  }
}

export { bytesToHex };
