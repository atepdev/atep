// Timing numbers for README: node scripts/bench.mjs
import { performance } from "node:perf_hooks";
import { init, keygen, Identity, sign, encrypt, verify } from "../dist/index.js";
const t0 = performance.now();
await init();
console.log(`init (compile + instantiate): ${(performance.now() - t0).toFixed(1)} ms`);
const time = (label, n, f) => {
  for (let i = 0; i < Math.min(n, 5); i++) f();
  const s = performance.now();
  for (let i = 0; i < n; i++) f();
  const ms = (performance.now() - s) / n;
  console.log(`${label.padEnd(44)} ${ms.toFixed(2)} ms/op`);
};
const a = keygen(false), b = keygen(true);
const now = Math.floor(Date.now() / 1000);
const payload = new TextEncoder().encode("x".repeat(256));
const signed = a.sign(payload, { issuedAt: now });
const sealed = encrypt(signed, b.publicBundle);
const trustAtt = a.sign(payload, { issuedAt: now, contentType: "application/atep-attestation+cbor", expiresAt: now + 600 });
time("keygen (with encryption keys)", 50, () => keygen(true).free());
time("sign (Ed25519 + ML-DSA-65, hedged)", 50, () => a.sign(payload, { issuedAt: now }));
time("encrypt (X25519 + ML-KEM-768, AES-256-GCM)", 100, () => encrypt(signed, b.publicBundle));
time("verify, signed trust document (steps 1-10)", 100, () => verify(trustAtt, {}, { now }));
time("verify, encrypted envelope (decrypt + steps 1-10)", 100, () => b.verify(sealed, {}, now));

// Full policy: one inline attestation chained to a root (3 signature checks per document).
import { withAttestations } from "../dist/index.js";
const root = keygen(false);
const att = root.issueAttestation({ subject: a.agentId, claim: "operator-of", issuedAt: now - 10, expiresAt: now + 3600, data: { operator: "Example" } });
const msg = encrypt(withAttestations(a.sign(payload, { issuedAt: now }), [att]), b.publicBundle);
const pol = { trust: { roots: [root.agentId], rules: [{ claim: "operator-of" }] }, known_bundles: [root.publicBundle] };
time("verify, encrypted + 1 attestation chain + policy", 100, () => b.verify(msg, pol, now));
