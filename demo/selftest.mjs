// Headless self-test: runs the scenario engine (real @atep/core crypto and
// verifier, no DOM) and asserts the expected outcome of every message.
// Usage: node demo/selftest.mjs

import { Engine, SCRIPT_LENGTH, T0 } from "./src/engine.mjs";

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

// Expected outcome per message in the scripted run: [tick, from, to, class, ok, step, error].
// ok is true (accepted), false (rejected at that step with that real error code) or "nd" (not delivered:
// controller offline, a transport outcome, never verified).
const EXPECT = [
  [1, "u2", "u1", "telemetry", true],
  [1, "u3", "u1", "telemetry", true],
  [1, "u4", "u1", "telemetry", true],
  [2, "u1", "u2", "motion", true],
  [2, "u1", "u3", "motion", true],
  [3, "u2", "u1", "sensor", true],
  [4, "u3", "u2", "motion", true],
  [4, "u3", "u4", "motion", false, 9, "claim_data_mismatch"],
  [5, "u2", "u1", "coordination", true],
  [5, "u2", "u4", "coordination", true],
  [6, "u1", "u2", "actuation", true],
  [7, "u3", "u1", "telemetry", true],
  [9, "u3", "u2", "motion", false, 8, "signer_revoked"],
  [9, "u3", "u1", "telemetry", false, 8, "signer_revoked"],
  [10, "u1", "u2", "motion", true],
  [10, "u2", "u1", "telemetry", true],
  [11, "u2", "u1", "coordination", true],
  [12, "u2", "u1", "telemetry", true],
  // controller offline from tick 13 to tick 19
  [13, "u2", "u1", "telemetry", "nd"],
  [13, "u1", "u2", "motion", "nd"],
  [13, "u2", "u4", "coordination", true],
  [13, "u4", "u2", "telemetry", true],
  [14, "u4", "u2", "coordination", true],
  [14, "u2", "u4", "telemetry", true],
  [15, "u4", "u2", "motion", true],
  [15, "u3", "u2", "motion", false, 8, "signer_revoked"],
  [16, "u2", "u4", "motion", false, 9, "claim_missing"],
  [17, "u4", "u2", "actuation", false, 9, "claim_missing"],
  [18, "u4", "u2", "safety", true],
  [19, "u2", "u4", "telemetry", true],
  [19, "u4", "u2", "telemetry", true],
  // controller back online
  [20, "u1", "u2", "motion", true],
  [20, "u2", "u1", "telemetry", true],
];

const show2 = (r) => (r.delivered === false ? "not delivered: controller offline" : show(r));

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
  const label = `t${x[0]} ${x[1]}->${x[2]} ${x[3]}: ${show2(r)}`;
  const base = r.tick === x[0] && r.from === x[1] && r.to === x[2] && r.cls === x[3];
  const same = x[4] === "nd"
    ? base && r.delivered === false && r.ok === null && r.step === null && r.error === null && r.effect.startsWith("not delivered: controller offline")
    : base && r.delivered === true && r.ok === x[4] && (x[4] || (r.step === x[5] && r.error === x[6]));
  check(label, same);
});
check("every envelope is ciphertext of realistic size (> 5 KB) with CBOR tag 0xd8 0x60", got.every((r) => r.size > 5000 && r.bytes[0] === 0xd8 && r.bytes[1] === 0x60));
check("accepted motion carries a fleet-controller or peer-motion claims chain", got.filter((r) => r.ok && r.cls === "motion").every((r) => r.claims.some((c) => /fleet-controller|peer-motion/.test(c.claim))));
check("Unit 3 is locked out after the SRL", e.u("u3").status === "revoked");
check("rejected motion was ignored (Unit 2 did not move to the keep-out waypoint)", !(e.u("u2").target.x === 60 && e.u("u2").target.y === 24));
check("rejected message carries 'ignored' effect", got.find((r) => r.ok === false).effect.startsWith("ignored"));

console.log("\nMembers talk directly while the controller is offline (ticks 13 to 19)");
const at = (tick, from, to, cls) => got.find((r) => r.tick === tick && r.from === from && r.to === to && r.cls === cls);
const offlineRecs = got.filter((r) => r.tick >= 13 && r.tick <= 19);
check("the controller is marked offline for every message of ticks 13 to 19", offlineRecs.length > 0 && offlineRecs.every((r) => r.controllerOffline === true));
check("every message to or from Unit 1 in that window is not delivered, none is a verification result", offlineRecs.filter((r) => r.from === "u1" || r.to === "u1").every((r) => r.delivered === false && r.ok === null && r.step === null && r.error === null));
check("every other message in that window really went through the verifier", offlineRecs.filter((r) => r.from !== "u1" && r.to !== "u1").every((r) => r.delivered === true && typeof r.ok === "boolean"));
check("(a) Unit 2 and Unit 4 path reservation accepted, controller offline", at(13, "u2", "u4", "coordination").ok === true && at(13, "u2", "u4", "coordination").effect.includes("path reservation"));
check("(a) Unit 4 and Unit 2 task claim accepted, controller offline", at(14, "u4", "u2", "coordination").ok === true);
check("(a) Unit 2 and Unit 4 telemetry accepted, controller offline", at(13, "u4", "u2", "telemetry").ok && at(14, "u2", "u4", "telemetry").ok && at(19, "u2", "u4", "telemetry").ok && at(19, "u4", "u2", "telemetry").ok);
const pm = at(15, "u4", "u2", "motion");
check(`(b) peer motion Unit 4 to Unit 2 accepted (peer-motion names Unit 2): ${show(pm)}`, pm.ok && pm.claims.some((c) => /peer-motion/.test(c.claim)) && pm.effect.includes("moves to waypoint"));
const nameless = at(16, "u2", "u4", "motion");
check(`(b) peer motion from a member presenting no peer-motion rejected: ${show(nameless)}`, !nameless.ok && nameless.step === 9 && nameless.error === "claim_missing");
const notNamed = at(4, "u3", "u4", "motion");
check(`(b) peer motion whose peer-motion does not name the receiver rejected: ${show(notNamed)}`, !notNamed.ok && notNamed.step === 9 && notNamed.error === "claim_data_mismatch");
const act = at(17, "u4", "u2", "actuation");
check(`(c) actuation from a member to a peer rejected: ${show(act)}`, !act.ok && act.step === 9 && act.error === "claim_missing" && act.effect.startsWith("ignored"));
const es = at(18, "u4", "u2", "safety");
check(`(d) e-stop from certified Unit 4 to Unit 2 accepted: ${show(es)}`, es.ok && es.claims.some((c) => /safety-certified/.test(c.claim)) && es.effect.includes("stops at once"));
check("(d) the e-stop really stops Unit 2 for the moment, then it resumes", e.u("u2").mode !== "e-stopped" && e.u("u2").status === "active");
check("a revoked Unit 3 is still refused offline, from the list held earlier (step 8)", (() => { const r = at(15, "u3", "u2", "motion"); return !r.ok && r.step === 8 && r.error === "signer_revoked"; })());

console.log("\nDecrypt controls");
const accepted = got.find((r) => r.ok && r.cls === "motion" && r.from === "u1");
const rcv = e.openAsRecipient(accepted);
check("recipient decrypts with own key and sees plaintext command", rcv.ok && rcv.payload.command === "waypoint" && rcv.payload.x === accepted.payload.x);
check("recipient result lists the verified claims chain", rcv.verify.ok && rcv.verify.claims.length > 0 && rcv.verify.claims[0].chain.length >= 1);
const obs = e.openAsObserver(accepted);
check("outside observer cannot decrypt (real failure)", obs.ok === false && /step 2/.test(obs.error) && obs.error.includes("not_addressed_to_recipient"), obs.error);
check("observer verify also fails at step 2", obs.verify.ok === false && obs.verify.step === 2);
const rejected = got.find((r) => r.ok === false && r.step === 8);
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

console.log("\nController offline plus stale revocation list");
check("controller comes back online by the script", e.controllerOffline === false);
e.setControllerOffline(true);
const so = e.setStale(true);
check(`(e) probes run between members while the controller is offline: ${so.map((r) => r.from + ">" + r.to).join(" ")}`, so.length === 3 && so.every((r) => r.from !== "u1" && r.to !== "u1" && r.delivered && r.controllerOffline));
check(`(e) peer motion fails closed at step 9 with a stale list: ${show(so[0])}`, !so[0].ok && so[0].step === 9 && so[0].error === "claim_missing");
check("(e) it fails because of the stale list: the same envelope verifies with a fresh list", so[0].staleCaused === true);
check(`(e) telemetry continues with a warning: ${show(so[1])}`, so[1].ok && so[1].warnings.length > 0 && /past next-update/.test(so[1].warnings[0]));
check(`(e) e-stop still accepted, with a warning: ${show(so[2])}`, so[2].ok && so[2].warnings.length > 0);
const ctl = e.send("u1", "u2", "motion", { command: "waypoint", x: 28, y: 36, speed: 3 });
check("(e) the controller stays unreachable meanwhile (not delivered)", ctl.delivered === false && ctl.ok === null);
const sf = e.setStale(false);
check("(e) with a fresh list again, peer motion, telemetry and e-stop all verify offline", sf.length === 3 && sf.every((r) => r.ok === true));

console.log("\nAttacks while the controller is offline");
const rp = e.attack("replay");
check(`replay offline stays between delivered units: ${show(rp)}`, rp.from !== "u1" && rp.to !== "u1" && !rp.ok && rp.step === 6 && rp.error === "nonce_replayed");
const tm = e.attack("tamper");
check(`tamper offline (Unit 2 to Unit 4): ${show(tm)}`, tm.to === "u4" && !tm.ok && tm.step === 2 && tm.error === "aead_failure");
const nc = e.attack("noclaim");
check(`motion without a delegation offline (Unit 2 to Unit 4): ${show(nc)}`, nc.to === "u4" && !nc.ok && nc.step === 9 && nc.error === "claim_missing");

console.log("\nA revocation cannot reach units while the controller is offline");
const e2 = await Engine.create();
e2.setControllerOffline(true);
check("revocation signed while offline is pending, not enforced", e2.revokeUnit3() !== null && e2.pendingRevoke !== null && e2.u("u3").status === "active");
e2.now = T0 + 10;
const still = e2.send("u3", "u2", "motion", { command: "waypoint", x: 36, y: 22, speed: 2 });
check(`Unit 3 is still accepted by Unit 2 (the list never arrived): ${show(still)}`, still.ok === true);
e2.setControllerOffline(false);
check("controller back online delivers the pending list", e2.pendingRevoke === null && e2.u("u3").status === "revoked");
const after = e2.send("u3", "u2", "motion", { command: "waypoint", x: 36, y: 22, speed: 2 });
check(`Unit 3 is refused afterwards: ${show(after)}`, !after.ok && after.step === 8 && after.error === "signer_revoked");
e2.free();

console.log("\nCiphertext previews");
const hexAll = [...got, ...e.log].every((r) => r.preview.length === 96);
check("hex previews are ciphertext only (48 bytes shown per envelope)", hexAll);

console.log(`\n${pass} passed, ${fail} failed`);
e.free();
process.exit(fail ? 1 : 0);
