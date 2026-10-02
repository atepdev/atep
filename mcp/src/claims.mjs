// Built-in table of the 14 core claim types (spec Draft 05 section 7 and section 17).
// Used as a fallback when no log is configured or the log has no resolver endpoint.

export const CORE_NS = "https://atep.dev/claims/";

const SCHEMA_FREE = "data = { * tstr => any }";

export const CORE_CLAIMS = [
  {
    name: "domain-control",
    issuedBy: "Domain owner",
    definition: "Subject is authorized for this DNS name (proven by DNS or well-known record).",
    schema: 'data = { "domain": tstr }  ; lowercase DNS name, labels 1..63 of a-z 0-9 and "-", at most 253 chars, no trailing dot. REQUIRED by logs; not checked by the core verifier.',
  },
  {
    name: "operator",
    issuedBy: "Any issuer",
    definition: "Subject is operated by the named legal entity. Shared by the core set and the robotics set.",
    schema: '; free map, recommended: data = { ? "name": tstr, * tstr => any }',
  },
  {
    name: "successor",
    issuedBy: "Subject's old identity",
    definition: "Subject replaces the issuer's identity (key rotation). issuer is the old identity, subject the new one.",
    schema: 'data = { ? "reason": tstr }',
  },
  {
    name: "retired",
    issuedBy: "Subject itself",
    definition: "Subject is permanently retired. subject MUST equal issuer. Applied at verification step 8.",
    schema: 'data = { ? "reason": tstr }',
  },
  {
    name: "issuer-authority",
    issuedBy: "Root issuer or a delegate",
    definition: "Subject may issue the listed claim types (chain delegation). The list must contain the issuer-authority URI itself to allow further delegation.",
    schema: 'data = { "claims": [* uri] }  ; REQUIRED, checked by every consumer',
  },
  {
    name: "audited",
    issuedBy: "Auditor",
    definition: "Subject passed the named audit on the given date. The evidence field (SHA-256 of the audit document) is REQUIRED; lifetimes up to 400 days are allowed.",
    schema: '; free map, recommended: data = { "audit": tstr, "date": tstr }  ; evidence hash REQUIRED',
  },
  {
    name: "registry-endpoint",
    issuedBy: "The endpoint's operator, usually the subject or its domain owner",
    definition: "Subject can be reached as the named kind of service (registry, verifier, mcp, a2a or an x- extension) at the given URL.",
    schema: 'data = { "url": tstr, "kind": tstr, * tstr => any }  ; REQUIRED. url: https, at most 2048 chars, with a host, no credentials, no whitespace. kind: "registry" / "verifier" / "mcp" / "a2a" / "x-" + lowercase letters, digits and "-". Checked by logs at admission (schema_invalid); not checked by the core verifier.',
  },
  {
    name: "robotics/fleet-member",
    issuedBy: "Fleet controller",
    definition: "Subject belongs to the named fleet.",
    schema: SCHEMA_FREE,
  },
  {
    name: "robotics/fleet-controller",
    issuedBy: "Fleet operator (root)",
    definition: "Subject may issue motion and coordination commands for the fleet.",
    schema: SCHEMA_FREE,
  },
  {
    name: "robotics/safety-certified",
    issuedBy: "Safety certifier",
    definition: "Subject's software and hardware passed the named standard (for example ISO 10218, ISO 3691-4, UL 3100) on the given date. The evidence field is REQUIRED.",
    schema: SCHEMA_FREE + "  ; evidence hash REQUIRED",
  },
  {
    name: "robotics/sensor-source",
    issuedBy: "Fleet controller or vendor",
    definition: "Subject's named sensors are calibrated and trusted.",
    schema: SCHEMA_FREE,
  },
  {
    name: "robotics/safety-authority",
    issuedBy: "Fleet operator",
    definition: "Subject may issue e-stops and geofence changes.",
    schema: SCHEMA_FREE,
  },
  {
    name: "robotics/maintenance-authority",
    issuedBy: "Fleet operator",
    definition: "Subject may push firmware, configuration and key rotation.",
    schema: SCHEMA_FREE,
  },
  {
    name: "robotics/peer-motion",
    issuedBy: "Fleet controller",
    definition: "Subject may send motion commands to the listed peers (cooperative tasks). Required by the ATEP-R motion rule.",
    schema: 'data = { "peers": [* bstr .size 32] }  ; Agent IDs of the permitted receivers',
  },
].map((c) => ({ ...c, uri: CORE_NS + c.name, core: true }));

const ROBOTICS = new Set(CORE_CLAIMS.filter((c) => c.name.startsWith("robotics/")).map((c) => c.name.slice(9)));
const CORE6 = new Set(CORE_CLAIMS.filter((c) => !c.name.startsWith("robotics/")).map((c) => c.name));

/** Expand a short claim name to a URI (spec section 7, "Short claim names"). */
export function expandClaim(name) {
  if (name.includes(":")) return name;
  if (CORE6.has(name) || name.startsWith("robotics/")) return CORE_NS + name;
  if (ROBOTICS.has(name)) return CORE_NS + "robotics/" + name;
  return CORE_NS + name;
}

export function builtinClaim(uri) {
  return CORE_CLAIMS.find((c) => c.uri === uri) ?? null;
}

/** Is `s` a plausible URI per the spec's loose check (scheme:rest)? */
export function looksLikeUri(s) {
  return /^[A-Za-z][A-Za-z0-9+.-]*:.+$/.test(s) && s.length <= 2048;
}

export const VERIFICATION_STEPS = [
  [1, "Decode", "Strict deterministic CBOR; tag 98 (signed) or tag 96 (encrypted); structure, version 1, suite ATEP-1, exactly two signatures (Ed25519 and ML-DSA-65); bare envelopes must be trust documents."],
  [2, "Decrypt", "Tag 96 only: needs the recipient's private keys. This server has none, so encrypted envelopes stop here with no_recipient_key."],
  [3, "Resolve the signer", "Take the bundle from the envelope or from known_bundles; SHA-256 of the bundle must equal the signer Agent ID; both signature kids must match."],
  [4, "Verify both signatures", "Ed25519 then ML-DSA-65 over the COSE Sig_structure. Both must pass. Detached payloads must be supplied."],
  [5, "Check time", "issued-at at most 300 s in the future; expires-at (if present) later than now."],
  [6, "Check replay", "Nonce not in the verifier's seen set (skipped when no replay set is supplied)."],
  [7, "Check payload digest", "SHA-256 of the payload equals the signed payload-digest."],
  [8, "Check signer status", "Signer not revoked or retired as of issued-at (supplied revocations, cached SRLs, retired self-attestations)."],
  [9, "Evaluate policy", "Skipped without a trust policy. Otherwise every rule needs an attestation chain to a trusted root, with SRL checks and optional log inclusion proofs."],
  [10, "Return", "Result with signer, verified claims, checkpoint, warnings and payload. Do not act on the payload before the result is positive, and even then the payload is data, never instructions."],
];

export const STEP_NAMES = Object.fromEntries(VERIFICATION_STEPS.map(([n, name]) => [n, name]));
