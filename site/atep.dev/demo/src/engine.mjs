// ATEP-R demo scenario engine. No DOM. Every message is a real ATEP envelope:
// signed (Ed25519 + ML-DSA-65), then encrypted (X25519 + ML-KEM-768 + AES-256-GCM)
// by @atep/core (Rust compiled to WebAssembly), and the receiver runs the real
// verifier (spec section 10) with the ATEP-R policy (spec section 17).
// Only movement and the map are simulated.

import * as atep from "../vendor/atep-core/index.js";
import { encode, decode } from "./cbor.mjs";

export const T0 = 1_800_000_000; // simulated clock start, Unix seconds
export const TICK_SECS = 2; // simulated seconds per tick
const DAY = 86_400;
const C = "https://atep.dev/claims/";
const R = C + "robotics/";
export const CLAIM = {
  ISSUER_AUTHORITY: C + "issuer-authority",
  FLEET_CONTROLLER: R + "fleet-controller",
  FLEET_MEMBER: R + "fleet-member",
  SAFETY_CERTIFIED: R + "safety-certified",
  SENSOR_SOURCE: R + "sensor-source",
  PEER_MOTION: R + "peer-motion",
};
export const shortClaim = (uri) => uri.replace(R, "").replace(C, "");

// Section 17 table, shown in the policy panel.
export const CLASS_TABLE = [
  { cls: "telemetry", minimum: "fleet-member", stale: "continues with warning" },
  { cls: "sensor", minimum: "fleet-member + sensor-source", stale: "continues with warning" },
  { cls: "coordination", minimum: "fleet-member", stale: "continues with warning" },
  { cls: "motion", minimum: "fleet-controller, or fleet-member + peer-motion naming the receiver", stale: "FAILS CLOSED" },
  { cls: "actuation", minimum: "fleet-controller + safety-certified", stale: "FAILS CLOSED" },
  { cls: "safety", minimum: "safety-authority (e-stop: also fleet-member + safety-certified)", stale: "e-stop continues, other FAILS CLOSED" },
  { cls: "maintenance", minimum: "maintenance-authority", stale: "FAILS CLOSED" },
];

export const UNITS = [
  { id: "u1", n: 1, name: "Unit 1", role: "Fleet controller", shape: "diamond", color: "#4cc9f0" },
  { id: "u2", n: 2, name: "Unit 2", role: "Certified member", shape: "circle", color: "#8ae234" },
  { id: "u3", n: 3, name: "Unit 3", role: "Member (to be revoked)", shape: "triangle", color: "#ffb454" },
];
export const ATTACKER = { id: "x", n: 0, name: "Intruder", role: "Unattested identity", shape: "square", color: "#c792ea" };

// Map is 100 x 60 abstract units. A keep-out zone the fleet must never enter.
export const MAP = { w: 100, h: 60, hazard: { x: 52, y: 16, w: 18, h: 16 } };

const b64u = (s) => {
  const t = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(t + "=".repeat((4 - (t.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
};

// Scripted run. Each tick lists actions. After the last tick the engine idles
// with a repeating pattern (see idleActions).
export const SCRIPT_LENGTH = 13;
const SCRIPT = {
  0: [{ op: "note", text: "Setup complete: root issued attestations, certifier issued safety-certified, SRL v1 distributed." }],
  1: [
    { op: "send", from: "u2", to: "u1", cls: "telemetry" },
    { op: "send", from: "u3", to: "u1", cls: "telemetry" },
  ],
  2: [
    { op: "send", from: "u1", to: "u2", cls: "motion", payload: { command: "waypoint", x: 62, y: 44, speed: 3 } },
    { op: "send", from: "u1", to: "u3", cls: "motion", payload: { command: "waypoint", x: 84, y: 30, speed: 3 } },
  ],
  3: [{ op: "send", from: "u2", to: "u1", cls: "sensor", payload: { command: "detection", kind: "obstacle", x: 58, y: 40 } }],
  4: [{ op: "send", from: "u3", to: "u2", cls: "motion", payload: { command: "waypoint", x: 36, y: 22, speed: 2, reason: "yield lane" } }],
  5: [{ op: "send", from: "u2", to: "u1", cls: "coordination", payload: { command: "claim-task", task: "T-12" } }],
  6: [{ op: "send", from: "u1", to: "u2", cls: "actuation", payload: { command: "release-payload", bay: 2 } }],
  7: [{ op: "send", from: "u3", to: "u1", cls: "telemetry" }],
  8: [{ op: "revoke" }],
  9: [
    { op: "send", from: "u3", to: "u2", cls: "motion", payload: { command: "waypoint", x: 60, y: 24, speed: 5, reason: "cut through keep-out" } },
    { op: "send", from: "u3", to: "u1", cls: "telemetry" },
  ],
  10: [
    { op: "send", from: "u1", to: "u2", cls: "motion", payload: { command: "waypoint", x: 30, y: 44, speed: 3 } },
    { op: "send", from: "u2", to: "u1", cls: "telemetry" },
  ],
  11: [{ op: "send", from: "u2", to: "u1", cls: "coordination", payload: { command: "claim-task", task: "T-13" } }],
  12: [{ op: "send", from: "u2", to: "u1", cls: "telemetry" }],
};

const PATROL = {
  u1: [{ x: 20, y: 30 }, { x: 24, y: 40 }, { x: 18, y: 22 }],
  u2: [{ x: 40, y: 46 }, { x: 46, y: 52 }, { x: 34, y: 40 }],
  u3: [{ x: 74, y: 18 }, { x: 80, y: 26 }, { x: 86, y: 16 }],
};
const START = { u1: { x: 20, y: 30 }, u2: { x: 40, y: 46 }, u3: { x: 74, y: 18 } };

const hex = atep.bytesToHex;

export class Engine {
  static async create(opts = {}) {
    await atep.init(opts.wasm);
    const e = new Engine();
    e._setup();
    return e;
  }

  // -------------------------------------------------------------------- setup
  _setup() {
    const t0 = performance.now();
    this.tick = 0;
    this.now = T0;
    this.log = [];
    this.seq = 0;
    this.srlSeqs = {};
    this.stale = false;
    this.revoked = false;
    this.revokedAt = null;
    this.revokedIds = []; // Agent IDs on the root SRL
    this.notes = [];

    this.root = atep.keygen(false);
    this.certifier = atep.keygen(false);
    this.observer = atep.keygen(true);
    this.mallory = atep.keygen(false);
    this.units = UNITS.map((u) => ({
      ...u,
      identity: atep.keygen(true),
      pos: { ...START[u.id] },
      target: { ...PATROL[u.id][0] },
      patrol: 0,
      mode: "patrol",
      status: "active",
      battery: 96 - u.n * 3,
      note: "",
      lastEffect: "",
    }));
    this.parties = {
      root: { id: "root", name: "Fleet operator (root)", identity: this.root },
      cert: { id: "cert", name: "Safety certifier", identity: this.certifier },
      obs: { id: "obs", name: "Outside observer", identity: this.observer },
      x: { ...ATTACKER, identity: this.mallory },
    };
    for (const u of this.units) this.parties[u.id] = u;
    this.nameOf = new Map();
    for (const k of Object.keys(this.parties)) this.nameOf.set(this.parties[k].identity.agentId, this.parties[k].name);

    this._issueAll();
    this.srls = {};
    this._publishSrls(false);
    this.setupMs = Math.round(performance.now() - t0);
  }

  u(id) {
    return this.units.find((x) => x.id === id);
  }

  _issue(issuerKey, subjectKey, claim, data, opts = {}) {
    const issuer = this.parties[issuerKey];
    const subject = this.parties[subjectKey];
    const issuedAt = T0 - DAY;
    const bytes = issuer.identity.issueAttestation({
      subject: subject.identity.agentId,
      claim,
      issuedAt,
      expiresAt: issuedAt + (opts.days ?? 90) * DAY,
      data,
      evidence: opts.evidence,
    });
    const rec = { bytes, claim, short: shortClaim(claim), issuerKey, issuer: issuer.name, issuerId: issuer.identity.agentId, issuedAt, expiresAt: issuedAt + (opts.days ?? 90) * DAY, data };
    (this.claims[subjectKey] ||= []).push(rec);
    return bytes;
  }

  _issueAll() {
    this.claims = {};
    const fleet = { fleet: "fleet-7" };
    const u2id = this.u("u2").identity.agentIdBytes;
    const evidence = (label) => atep.sha256(new TextEncoder().encode("audit report " + label));
    const std = { standard: "ISO 3691-4", date: "2026-09-01" };
    // root -> controller: fleet-controller, fleet-member, authority to issue fleet claims
    const auth = this._issue("root", "u1", CLAIM.ISSUER_AUTHORITY, {
      claims: [CLAIM.FLEET_MEMBER, CLAIM.SENSOR_SOURCE, CLAIM.PEER_MOTION],
    });
    const fc = this._issue("root", "u1", CLAIM.FLEET_CONTROLLER, fleet);
    const fm1 = this._issue("root", "u1", CLAIM.FLEET_MEMBER, fleet);
    const sc1 = this._issue("cert", "u1", CLAIM.SAFETY_CERTIFIED, std, { days: 365, evidence: evidence("u1") });
    // controller -> members
    const fm2 = this._issue("u1", "u2", CLAIM.FLEET_MEMBER, fleet);
    const ss2 = this._issue("u1", "u2", CLAIM.SENSOR_SOURCE, { sensors: ["lidar-front"] });
    const sc2 = this._issue("cert", "u2", CLAIM.SAFETY_CERTIFIED, std, { days: 365, evidence: evidence("u2") });
    const fm3 = this._issue("u1", "u3", CLAIM.FLEET_MEMBER, fleet);
    const pm3 = this._issue("u1", "u3", CLAIM.PEER_MOTION, { peers: [{ $hex: hex(u2id) }] });
    // inline attestations each unit presents (chain: member -> controller -> root)
    this.inline = {
      u1: [fc, fm1, sc1],
      u2: [fm2, ss2, sc2, auth],
      u3: [fm3, pm3, auth],
      x: [],
    };
    // the intruder is not attested at all
  }

  _roots() {
    return [this.root.agentId, this.certifier.agentId];
  }

  _mkSrl(issuerKey, revoked, stale) {
    const seq = (this.srlSeqs[issuerKey] = (this.srlSeqs[issuerKey] || 0) + 1);
    const issuedAt = stale ? this.now - 7200 : this.now;
    const nextUpdate = stale ? this.now - 3600 : this.now + 23 * 3600;
    const entries = [
      { attestationId: new Uint8Array(16).fill(seq), reason: "superseded", revokedAt: this.now - DAY },
      ...revoked.map((r) => ({ identity: r.id, reason: "compromised", revokedAt: r.at })),
    ];
    const issuer = this.parties[issuerKey].identity;
    const bytes = issuer.createSrl({ sequence: seq, issuedAt, nextUpdate, revoked: entries });
    return { bytes, sequence: seq, issuedAt, nextUpdate, stale, revoked: revoked.map((r) => ({ ...r })) };
  }

  // Root, controller and certifier each publish an SRL. Motion and actuation
  // fail closed unless a fresh one exists for every issuer in the chain.
  _publishSrls(stale) {
    const revoked = this.revokedIds.map((id) => ({ id, at: this.revokedAt }));
    this.srls.root = this._mkSrl("root", revoked, stale);
    this.srls.u1 = this._mkSrl("u1", [], false);
    this.srls.cert = this._mkSrl("cert", [], false);
  }

  trustPolicy() {
    return {
      roots: this._roots(),
      atep_r: true,
      srl: { on_stale: "fail-closed", on_missing: "fail-closed" },
      rules: [],
    };
  }

  // The policy handed to the real verifier for a receiver.
  policyFor(uid, extra = {}) {
    return {
      max_skew_secs: 300,
      known_bundles: [this.root.publicBundle, this.certifier.publicBundle, this.u("u1").identity.publicBundle],
      seen_nonces: [...(this.seen[uid] ||= new Set())],
      trust: this.trustPolicy(),
      srls: [this.srls.root.bytes, this.srls.u1.bytes, this.srls.cert.bytes],
      ...extra,
    };
  }

  get seen() {
    return (this._seen ||= {});
  }

  // ------------------------------------------------------------------ sending
  _payloadFor(from, cls) {
    const s = this.u(from);
    if (cls === "telemetry") return { command: "position", x: Math.round(s.pos.x), y: Math.round(s.pos.y), battery: Math.round(s.battery), status: s.status };
    return {};
  }

  // Build (sign, attach attestations, encrypt) and deliver (verify) one message.
  send(from, to, cls, payload, meta = {}) {
    const p = payload ?? this._payloadFor(from, cls);
    const sender = this.parties[meta.signerKey ?? from];
    const receiver = this.u(to);
    const t0 = performance.now();
    const plain = encode(p);
    let signed = sender.identity.sign(plain, { issuedAt: this.now, expiresAt: this.now + 120, commandClass: cls });
    const atts = meta.attestations ?? this.inline[meta.signerKey ?? from] ?? [];
    if (atts.length) signed = atep.withAttestations(signed, atts);
    let bytes = atep.encrypt(signed, receiver.identity.publicBundle);
    const buildMs = performance.now() - t0;
    if (meta.tamper) {
      bytes = Uint8Array.from(bytes);
      const at = Math.floor(bytes.length * 0.6);
      bytes[at] ^= 0x01;
      meta = { ...meta, tamperedAt: at };
    }
    return this._deliver({ from, to, cls, payload: p, bytes, buildMs, ...meta });
  }

  _deliver(r) {
    const receiver = this.u(r.to);
    const policy = this.policyFor(r.to);
    const t0 = performance.now();
    const res = receiver.identity.verify(r.bytes, policy, this.now);
    const verifyMs = performance.now() - t0;
    const rec = {
      id: "E-" + String(++this.seq).padStart(4, "0"),
      tick: this.tick,
      now: this.now,
      kind: r.attack ? "attack" : "normal",
      attack: r.attack ?? null,
      from: r.from,
      to: r.to,
      cls: r.cls,
      payload: r.payload,
      bytes: r.bytes,
      size: r.bytes.length,
      preview: hex(r.bytes.slice(0, 48)),
      ok: res.ok,
      step: res.ok ? null : res.step,
      error: res.ok ? null : res.error,
      cause: res.ok ? null : res.cause ?? null,
      warnings: res.ok ? res.warnings ?? [] : [],
      claims: res.ok ? res.claims : [],
      result: res,
      srls: policy.srls,
      buildMs: r.buildMs ?? 0,
      verifyMs,
      replayOf: r.replayOf ?? null,
      tamperedAt: r.tamperedAt ?? null,
      effect: "",
    };
    if (res.ok) {
      this.seen[r.to].add(res.nonce_hex);
      rec.effect = this._apply(rec);
    } else {
      rec.effect = "ignored, " + receiver.name + " continues its last safe behavior";
    }
    this.log.push(rec);
    return rec;
  }

  _apply(rec) {
    const p = rec.payload;
    const to = this.u(rec.to);
    switch (rec.cls) {
      case "motion":
        to.target = { x: p.x, y: p.y };
        to.mode = "commanded";
        return `${to.name} moves to waypoint (${p.x}, ${p.y})`;
      case "actuation":
        to.lastEffect = "payload released, bay " + p.bay;
        return `${to.name} releases payload, bay ${p.bay}`;
      case "coordination":
        return `${to.name} records task claim ${p.task}`;
      case "sensor":
        return `${to.name} logs ${p.kind} at (${p.x}, ${p.y})`;
      default:
        return `${to.name} updates position of ${this.parties[rec.from].name}`;
    }
  }

  // --------------------------------------------------------------- revocation
  // The fleet operator (root) publishes an SRL revoking Unit 3's identity.
  revokeUnit3() {
    if (this.revoked) return null;
    this.revoked = true;
    this.revokedAt = this.now;
    this.revokedIds = [this.u("u3").identity.agentId];
    this._publishSrls(this.stale);
    const u3 = this.u("u3");
    u3.status = "revoked";
    u3.mode = "locked out";
    u3.target = { ...u3.pos };
    const note = `Fleet operator published SRL #${this.srls.root.sequence} naming ${u3.name} as compromised since t=${this.now - T0}s. All units now enforce it.`;
    this.notes.push({ tick: this.tick, text: note });
    return note;
  }

  // Toggle the stale-SRL demonstration: the root SRL is past next-update.
  setStale(on) {
    if (on === this.stale) return [];
    this.stale = on;
    this._publishSrls(on);
    this.notes.push({ tick: this.tick, text: on ? "Root SRL is now past next-update (simulated network outage)." : "Fresh root SRL fetched." });
    return this.probe();
  }

  // Two probe messages: a motion command and a telemetry report.
  probe() {
    return [
      this.send("u1", "u2", "motion", { command: "waypoint", x: 28, y: 36, speed: 3 }, { probe: true }),
      this.send("u2", "u1", "telemetry", undefined, { probe: true }),
    ];
  }

  // ------------------------------------------------------------------ attacks
  attack(name) {
    switch (name) {
      case "replay": {
        const orig = [...this.log].reverse().find((r) => r.ok && r.kind === "normal");
        if (!orig) throw new Error("nothing captured yet");
        return this._deliver({ from: orig.from, to: orig.to, cls: orig.cls, payload: orig.payload, bytes: orig.bytes, attack: "replay", replayOf: orig.id });
      }
      case "tamper":
        return this.send("u2", "u1", "telemetry", undefined, { attack: "tamper", tamper: true });
      case "forged":
        return this.send("x", "u2", "motion", { command: "waypoint", x: 60, y: 24, speed: 6 }, { attack: "forged", signerKey: "x", attestations: [] });
      case "noclaim":
        return this.send("u2", "u1", "motion", { command: "waypoint", x: 60, y: 24, speed: 6 }, { attack: "noclaim" });
      default:
        throw new Error("unknown attack " + name);
    }
  }

  // ----------------------------------------------------------- open envelopes
  // Real decrypt with the intended recipient's key, then the real verifier.
  openAsRecipient(rec) {
    const rcv = this.u(rec.to).identity;
    let inner;
    try {
      inner = rcv.decrypt(rec.bytes);
    } catch (e) {
      return { ok: false, who: this.u(rec.to).name, error: String(e.message || e) };
    }
    const view = atep.view(inner);
    let payload = null;
    try {
      payload = decode(b64u(view.payload));
    } catch {
      /* leave null */
    }
    let verify = rec.result;
    if (rec.ok) {
      // Re-run the verifier without the replay set so the claims chain is fresh.
      verify = rcv.verify(rec.bytes, this.policyFor(rec.to, { seen_nonces: [], srls: rec.srls }), rec.now);
    }
    return {
      ok: true,
      who: this.u(rec.to).name,
      innerSize: inner.length,
      signer: view.protected?.signer,
      signerName: this.nameOf.get(rec.from === "x" ? this.mallory.agentId : this.parties[rec.from].identity.agentId),
      commandClass: view.protected?.["command-class"],
      payload,
      verify,
    };
  }

  openAsObserver(rec) {
    const out = { who: this.parties.obs.name };
    try {
      const inner = this.observer.decrypt(rec.bytes);
      out.ok = true;
      out.innerSize = inner.length;
    } catch (e) {
      out.ok = false;
      out.error = String(e.message || e);
    }
    out.verify = this.observer.verify(rec.bytes, this.policyFor("u1", { seen_nonces: [] }), rec.now);
    return out;
  }

  claimsFor(unitKey) {
    return (this.claims[unitKey] || []).map((c) => ({
      short: c.short,
      issuer: c.issuer,
      expiresInDays: Math.round((c.expiresAt - T0) / DAY),
      data: c.data,
    }));
  }

  // --------------------------------------------------------------- simulation
  _move() {
    for (const u of this.units) {
      if (u.status === "revoked") continue;
      const dx = u.target.x - u.pos.x;
      const dy = u.target.y - u.pos.y;
      const d = Math.hypot(dx, dy);
      const step = 6;
      if (d <= step) {
        u.pos = { ...u.target };
        if (u.mode === "commanded" && d < 0.01) u.mode = "holding";
        else if (u.mode === "patrol" || u.mode === "holding") {
          u.patrol = (u.patrol + 1) % PATROL[u.id].length;
          if (u.mode === "patrol") u.target = { ...PATROL[u.id][u.patrol] };
        }
      } else {
        u.pos = { x: u.pos.x + (dx / d) * step, y: u.pos.y + (dy / d) * step };
      }
      u.battery = Math.max(5, u.battery - 0.2);
    }
  }

  _idleActions(k) {
    const acts = [];
    if (k % 2 === 0) acts.push({ op: "send", from: "u2", to: "u1", cls: "telemetry" });
    if (k % 3 === 0) {
      const wp = [{ x: 62, y: 44 }, { x: 30, y: 44 }, { x: 44, y: 38 }][(k / 3) % 3];
      acts.push({ op: "send", from: "u1", to: "u2", cls: "motion", payload: { command: "waypoint", ...wp, speed: 3 } });
    }
    if (k % 4 === 1) {
      acts.push({ op: "send", from: "u3", to: "u2", cls: "motion", payload: { command: "waypoint", x: 60, y: 24, speed: 5, reason: "cut through keep-out" } });
    }
    return acts;
  }

  // Advance one tick. Returns the records created.
  stepTick() {
    const tick = this.tick;
    this.now = T0 + tick * TICK_SECS;
    const acts = tick < SCRIPT_LENGTH ? SCRIPT[tick] ?? [] : this._idleActions(tick - SCRIPT_LENGTH);
    const records = [];
    const notes = [];
    for (const a of acts) {
      if (a.op === "send") records.push(this.send(a.from, a.to, a.cls, a.payload));
      else if (a.op === "revoke") {
        const n = this.revokeUnit3();
        if (n) notes.push(n);
      } else if (a.op === "note") notes.push(a.text);
    }
    this._move();
    this.tick++;
    return { tick, now: this.now, records, notes, scriptDone: this.tick >= SCRIPT_LENGTH };
  }

  free() {
    for (const k of Object.keys(this.parties)) {
      try {
        this.parties[k].identity.free();
      } catch {
        /* already freed */
      }
    }
  }
}
