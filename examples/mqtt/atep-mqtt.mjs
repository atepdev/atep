// ATEP-R over MQTT: the MQTT payload IS the envelope bytes (sign-then-encrypt, tag 96).
// Topic convention (spec section 17 names fleet, unit and class): fleet/<fleet>/<unit>/<class>.
// The topic is routing metadata and is NOT trusted: the receiver checks it against the
// signed command-class header after verification.
import mqtt from "mqtt";
import { init, encrypt, verify, withAttestations, hexToBytes } from "@atep/core";

export { init };
export const CLASSES = ["telemetry", "sensor", "coordination", "motion", "actuation", "safety", "maintenance"];
export const topicFor = (fleet, unit, cls) => `fleet/${fleet}/${unit}/${cls}`;
const nowSecs = () => Math.floor(Date.now() / 1000);

/** Build one ATEP-R envelope. `to` is the recipient unit's public bundle (it opens the tag 96 wrapper). */
export function buildEnvelope({ cls, sender, attestations, payload, to, ttl = 120 }) {
  const t = nowSecs();
  let signed = sender.sign(new TextEncoder().encode(payload), { issuedAt: t, expiresAt: t + ttl, commandClass: cls });
  signed = withAttestations(signed, attestations);
  return encrypt(signed, to);
}

/** Publish envelope bytes as the MQTT payload, unchanged. */
export const publishEnvelope = (client, { fleet, unit, cls, bytes }) =>
  client.publishAsync(topicFor(fleet, unit, cls), Buffer.from(bytes), { qos: 1 });

/**
 * Subscribe as `unit` and call onMessage({ok, ...}) for every envelope on fleet/<fleet>/<unit>/+.
 * ATEP-R is a verifier setting (atep_r: true): unencrypted or class-less envelopes are refused.
 */
export async function subscribeVerified(client, { fleet, unit, identity, rootId, rootBundle, onMessage }) {
  const seen = new Set(); // replay set, filled only after full success
  client.on("message", (topic, bytes) => {
    const policy = { trust: { roots: [rootId], atep_r: true, rules: [] }, known_bundles: [rootBundle], seen_nonces: [...seen] };
    const r = verify(new Uint8Array(bytes), policy, { recipient: identity, now: nowSecs() });
    if (!r.ok) return onMessage({ ok: false, topic, step: r.step, error: r.error });
    const topicClass = topic.split("/")[3];
    if (r.command_class !== topicClass) {
      return onMessage({ ok: false, topic, step: 0, error: "topic_class_mismatch" });
    }
    seen.add(r.nonce_hex);
    onMessage({ ok: true, topic, signer: r.signer, cls: r.command_class, payload: new TextDecoder().decode(hexToBytes(r.payload_hex)) });
  });
  await client.subscribeAsync(topicFor(fleet, unit, "+"), { qos: 1 });
}

export const connect = (url) => mqtt.connectAsync(url);
