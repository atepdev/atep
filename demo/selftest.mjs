// Headless self-test: runs the scenario engine (real @atep/core crypto and
// verifier, no DOM) and asserts the expected outcome of every message.
// Usage: node demo/selftest.mjs

import { Engine, SCRIPT_LENGTH } from "./src/engine.mjs";

let pass = 0;
let fail = 0;
const check = (name, cond, detail = "") => {
  if (cond) pass++;
  else fail++;
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${cond || !detail ? "" : "  <- " + detail}`);
};
const show = (r) => (r.ok ? "accepted" : `rejected step ${r.step} ${r.error}`);

const e = await Engine.create();
console.log(`ATEP-R demo self-test (identities, attestations and SRLs created in ${e.setupMs} ms)\n`);

// Expected outcome per message in the scripted run: [tick, from, to, class, ok, step, error]
const EXPECT = [
  [1, "u2", "u1", "telemetry", true],
  [1, "u3", "u1", "telemetry", true],
  [2, "u1", "u2", "motion", true],
  [2, "u1", "u3", "motion", true],
  [3, "u2", "u1", "sensor", true],
  [4, "u3", "u2", "motion", true],
  [5, "u2", "u1", "coordination", true],
  [6, "u1", "u2", "actuation", true],
  [7, "u3", "u1", "telemetry", true],
  [9, "u3", "u2", "motion", false, 8, "signer_revoked"],
  [9, "u3", "u1", "telemetry", false, 8, "signer_revoked"],
  [10, "u1", "u2", "motion", true],
  [10, "u2", "u1", "telemetry", true],
  [11, "u2", "u1", "coordination", true],
  [12, "u2", "u1", "telemetry", true],
];

console.log("Scripted run");
const got = [];
let notes = [];
for (let i = 0; i < SCRIPT_LENGTH; i++) {
  const t = e.stepTick();
  got.push(...t.records);
  notes.push(...t.notes);
}
check("script produced the expected number of envelopes", got.length === EXPECT.length, `${got.length} vs ${EXPECT.length}`);
EXPECT.forEach((x, i) => {
  const r = got[i];
  if (!r) return check(`message ${i}`, false, "missing");
  const label = `t${x[0]} ${x[1]}->${x[2]} ${x[3]}: ${show(r)}`;
  const same = r.tick === x[0] && r.from === x[1] && r.to === x[2] && r.cls === x[3] && r.ok === x[4] && (x[4] || (r.step === x[5] && r.error === x[6]));
  check(label, same);
});
check("every envelope is ciphertext of realistic size (> 5 KB) with CBOR tag 0xd8 0x60", got.every((r) => r.size > 5000 && r.bytes[0] === 0xd8 && r.bytes[1] === 0x60));
check("accepted motion carries a fleet-controller or peer-motion claims chain", got.filter((r) => r.ok && r.cls === "motion").every((r) => r.claims.some((c) => /fleet-controller|peer-motion/.test(c.claim))));
check("Unit 3 is locked out after the SRL", e.u("u3").status === "revoked");
check("rejected motion was ignored (Unit 2 did not move to the keep-out waypoint)", !(e.u("u2").target.x === 60 && e.u("u2").target.y === 24));
check("rejected message carries 'ignored' effect", got.find((r) => !r.ok).effect.startsWith("ignored"));

console.log("\nDecrypt controls");
const accepted = got.find((r) => r.ok && r.cls === "motion" && r.from === "u1");
const rcv = e.openAsRecipient(accepted);
check("recipient decrypts with own key and sees plaintext command", rcv.ok && rcv.payload.command === "waypoint" && rcv.payload.x === accepted.payload.x);
check("recipient result lists the verified claims chain", rcv.verify.ok && rcv.verify.claims.length > 0 && rcv.verify.claims[0].chain.length >= 1);
const obs = e.openAsObserver(accepted);
check("outside observer cannot decrypt (real failure)", obs.ok === false && /step 2/.test(obs.error) && obs.error.includes("not_addressed_to_recipient"), obs.error);
check("observer verify also fails at step 2", obs.verify.ok === false && obs.verify.step === 2);
const rejected = got.find((r) => !r.ok);
const rrej = e.openAsRecipient(rejected);
check("recipient can open a rejected envelope but verification stays rejected", rrej.ok && rrej.verify.ok === false && rrej.verify.step === 8);

console.log("\nAttacks (each really attempted)");
const attacks = [
  ["replay", 6, "nonce_replayed"],
  ["tamper", 2, "aead_failure"],
  ["forged", 9, "claim_missing"],
  ["noclaim", 9, "claim_missing"],
];
for (const [name, step, error] of attacks) {
  const r = e.attack(name);
  check(`attack ${name}: ${show(r)}`, r.ok === false && r.step === step && r.error === error && r.kind === "attack");
}

console.log("\nStale SRL (optional toggle, fail-closed)");
const on = e.setStale(true);
check(`motion with stale root SRL: ${show(on[0])}`, !on[0].ok && on[0].step === 9 && on[0].error === "srl_stale");
check(`telemetry with stale root SRL continues: ${show(on[1])}`, on[1].ok && on[1].warnings.length > 0);
const off = e.setStale(false);
check("fresh SRL restores motion", off[0].ok && off[1].ok);

console.log("\nCiphertext previews");
const hexAll = [...got, ...e.log].every((r) => r.preview.length === 96);
check("hex previews are ciphertext only (48 bytes shown per envelope)", hexAll);

console.log(`\n${pass} passed, ${fail} failed`);
e.free();
process.exit(fail ? 1 : 0);
