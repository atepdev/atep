"""Vector runner: python -m atep_py.vectors check <vectors-dir>"""
import hashlib
import json
import os
import sys
import time

from . import cbor, identity, envelope as E
from .core import Reject, Context
from . import verify as V
from . import srl as srlmod
from . import logs
from . import anchors, admission, domain as domainmod
from .policy import TrustPolicy


def _hex(s):
    return bytes.fromhex(s)


def check_identity(d, raw):
    i = identity.Identity(d["inputs"]["seeds"])
    ex = d["expected"]
    problems = []
    if i.bundle != raw:
        problems.append("bundle bytes differ")
    if identity.agent_id_text(i.agent_id) != ex["agent_id"]:
        problems.append("agent_id differs")
    if identity.agent_id_did(i.agent_id) != ex["did"]:
        problems.append("did differs")
    if i.agent_id.hex() != ex["agent_id_hex"]:
        problems.append("agent_id_hex differs")
    if len(i.bundle) != ex["bundle_len"]:
        problems.append("bundle_len differs")
    if i.keys["ed25519"].hex() != ex["ed25519_public_hex"]:
        problems.append("ed25519 public differs")
    if hashlib.sha256(i.keys["mldsa65"]).hexdigest() != ex["mldsa65_public_sha256"]:
        problems.append("mldsa65 public hash differs")
    try:
        if identity.parse_agent_id(ex["agent_id"]) != i.agent_id or identity.parse_agent_id(ex["did"]) != i.agent_id:
            problems.append("agent id parse mismatch")
        if identity.parse_agent_id(ex["agent_id"].upper()) is not None:
            problems.append("uppercase accepted")
    except ValueError:
        pass
    return problems


def check_signing(d, raw):
    i = d["inputs"]
    s = identity.Identity(i["signer_seeds"])
    env = E.sign(s, _hex(i["payload_hex"]), i["content_type"], _hex(i["nonce_hex"]), i["issued_at"],
                 i["expires_at"], i["detached"], i["include_bundle"])
    ex = d["expected"]
    problems = []
    if env != raw:
        problems.append("envelope bytes differ")
    if identity.agent_id_text(s.agent_id) != ex["signer"]:
        problems.append("signer differs")
    if hashlib.sha256(_hex(i["payload_hex"])).hexdigest() != ex["payload_digest_hex"]:
        problems.append("payload digest differs")
    if len(env) != ex["envelope_len"] or hashlib.sha256(env).hexdigest() != ex["envelope_sha256"]:
        problems.append("length or hash differs")
    return problems


def check_attestation(d, raw):
    i = d["inputs"]
    s = identity.Identity(i["issuer_seeds"])
    payload = {
        "subject": identity.parse_agent_id(i["subject"]),
        "issuer": s.agent_id,
        "claim": i["claim"],
        "data": cbor.loads(_hex(i["data_hex"])),
        "id": _hex(i["id_hex"]),
    }
    if i.get("evidence_hex"):
        payload["evidence"] = _hex(i["evidence_hex"])
    if i.get("evidence_uri"):
        payload["evidence-uri"] = i["evidence_uri"]
    pb = cbor.dumps(payload)
    env = E.sign(s, pb, E.CT_ATTESTATION, _hex(i["nonce_hex"]), i["issued_at"], i["expires_at"],
                 False, True)
    ex = d["expected"]
    problems = []
    if pb.hex() != ex["payload_hex"]:
        problems.append("payload differs")
    if env != raw:
        problems.append("envelope bytes differ")
    if identity.agent_id_text(s.agent_id) != ex["issuer"]:
        problems.append("issuer differs")
    if len(env) != ex["envelope_len"] or hashlib.sha256(env).hexdigest() != ex["envelope_sha256"]:
        problems.append("length or hash differs")
    return problems


def check_encryption(d, raw):
    i = d["inputs"]
    rcpt = identity.Identity(i["recipient_seeds"])
    r = i["randomness"]
    inner = _hex(i["inner_envelope_hex"])
    out, mid = E.encrypt(inner, rcpt, _hex(r["x25519_ephemeral_hex"]), _hex(r["mlkem_m_hex"]), _hex(r["iv_hex"]))
    ex = d["expected"]
    im = ex["intermediate"]
    problems = []
    got = {"eph_x25519_public_hex": mid["eph_pub"].hex(),
           "mlkem_ciphertext_sha256": hashlib.sha256(mid["kem_ct"]).hexdigest(),
           "ss_x25519_hex": mid["ss_x"].hex(), "ss_mlkem768_hex": mid["ss_pq"].hex(),
           "hkdf_info_hex": mid["info"].hex(), "aes_key_hex": mid["key"].hex()}
    for k, v in got.items():
        if im.get(k) != v:
            problems.append("intermediate %s differs" % k)
    if out != raw:
        problems.append("ciphertext bytes differ")
    if len(out) != ex["ciphertext_len"] or hashlib.sha256(out).hexdigest() != ex["ciphertext_sha256"]:
        problems.append("length or hash differs")
    # decrypt round trip
    from .core import decrypt
    ctx = Context(0, recipient=rcpt)
    try:
        inner2 = decrypt(cbor.loads(raw), ctx)
        if cbor.dumps(inner2) != inner:
            problems.append("decrypt differs")
    except Reject as e:
        problems.append("decrypt failed: %s" % e)
    return problems


def compare(expected, got):
    if expected == got:
        return []
    out = []
    if isinstance(expected, dict) and isinstance(got, dict):
        for k in sorted(set(expected) | set(got), key=str):
            if k not in got:
                out.append("missing %s" % k)
            elif k not in expected:
                out.append("unexpected %s" % k)
            else:
                out += ["%s.%s" % (k, p) if p else k for p in compare(expected[k], got[k])] or []
        return out
    return ["expected %r got %r" % (str(expected)[:200], str(got)[:200])]


def check_verify(d, raw):
    got = V.verify_json(raw, d["inputs"]["policy"])
    return compare(d["expected"], got)


def check_srl(d, raw):
    i = d["inputs"]
    ctx = Context(i["now"], check_replay=False)
    if i.get("cached_srl_hex"):
        srlmod.load_srl(_hex(i["cached_srl_hex"]), ctx, on_stale="fail-open")
    ex = d["expected"]
    try:
        entry, warns = srlmod.load_srl(raw, ctx, i.get("srl_policy", {}).get("on_stale", "fail-closed"))
        got = {"ok": True, "issuer": identity.agent_id_text(entry["issuer"]), "sequence": entry["sequence"],
               "issued_at": entry["issued_at"], "next_update": entry["next_update"],
               "stale": entry["stale"], "revoked": srlmod.describe(entry)}
        if warns:
            got["warnings"] = warns
    except Reject as r:
        got = r.as_dict()
    return compare(ex, got)


def check_srl_context(d, raw):
    """srl-context: load an SRL in the verifier's own context (cache, revocations, local store)."""
    i = d["inputs"]
    ctx = V.context_from_json({"now": i["now"], "known_bundles": i.get("known_bundles", []),
                               "revocations": i.get("revocations", []),
                               "attestations": i.get("attestations", [])})
    ctx.check_replay = False
    try:
        if i.get("cached_srl_hex"):
            srlmod.load_srl(_hex(i["cached_srl_hex"]), ctx, on_stale="fail-open")
        entry, warns = srlmod.load_srl(raw, ctx, i.get("srl_policy", {}).get("on_stale", "fail-closed"))
        got = {"ok": True, "issuer": identity.agent_id_text(entry["issuer"]), "sequence": entry["sequence"],
               "issued_at": entry["issued_at"], "next_update": entry["next_update"],
               "stale": entry["stale"], "revoked": srlmod.describe(entry)}
        if warns:
            got["warnings"] = warns
    except Reject as r:
        got = r.as_dict()
    return compare(d["expected"], got)


# Categories this implementation does not run, with the documented reason. A skip is named and counted.
SKIPS = {
    "log-admission": "atep-py is a verifier and has no transparency log; admission (spec section 9) "
                     "applies only to implementations that have a log",
    "monitor": "atep-py has no log monitor; the successor_chain alert (spec section 9) applies only to "
               "implementations that have a monitor",
}


def check_log(d, raw):
    i = d["inputs"]
    ctx = Context(i["now"], check_replay=False)
    trusted = set(identity.parse_agent_id(x) for x in i["trusted_logs"])
    kind = i["check"]
    try:
        if kind == "checkpoint":
            signer, p = logs.check_checkpoint(raw, ctx, trusted)
            got = {"ok": True, "checkpoint": logs.checkpoint_dict(signer, p)}
        elif kind == "inclusion":
            got = {"ok": True, "checkpoint": logs.check_inclusion(cbor.loads(raw), ctx, trusted)}
        elif kind == "consistency":
            got = dict(logs.check_consistency(raw, ctx, trusted), ok=True)
        elif kind == "split-view":
            got = dict(logs.check_split_view(raw, ctx, trusted), ok=True)
        else:
            return ["unknown check %s" % kind]
    except Reject as r:
        got = r.as_dict()
    return compare(d["expected"], got)


def check_checkpoint_hash(d, raw):
    i = d["inputs"]
    ctx = Context(i["now"], check_replay=False)
    trusted = set(identity.parse_agent_id(x) for x in i["trusted_logs"])
    try:
        signer, p, payload = logs.check_checkpoint_full(raw, ctx, trusted)
        got = {"ok": True, "checkpoint": logs.checkpoint_dict(signer, p),
               "checkpoint_hash": anchors.checkpoint_hash(payload).hex(), "payload_hex": payload.hex()}
    except Reject as r:
        got = r.as_dict()
    return compare(d["expected"], got)


def check_anchor_record(d, raw):
    ex = d["expected"]
    try:
        rec = anchors.decode_record(raw)
        got = {"ok": True, "record": rec}
    except anchors.AnchorRecordInvalid:
        return compare(ex, {"ok": False, "error": "anchor_record_invalid"})
    problems = compare(ex, got)
    if ex.get("ok") and anchors.encode_record(ex["record"]) != raw:
        problems.append("encoding the record does not give the file bytes")
    return problems


def check_chain_id(d, raw):
    kind = anchors.chain_id_kind(d["inputs"]["id"])
    got = {"ok": True, "kind": kind} if kind else {"ok": False}
    problems = compare(d["expected"], got)
    if cbor.loads(raw) != d["inputs"]["id"]:
        problems.append("cbor file is not the id text")
    return problems


def check_anchor_envelope(d, raw):
    i = d["inputs"]
    try:
        got = anchors.check_published_anchor(raw, Context(i["now"], check_replay=False), i["log"],
                                             i["checkpoint_hash_hex"])
    except Reject as r:
        got = r.as_dict()
    return compare(d["expected"], got)


def check_require_anchor(d, raw):
    try:
        t = TrustPolicy(d["inputs"]["policy"])
        got = {"ok": True, "require_anchor": t.require_anchor}
    except Reject:
        # a configuration error has no step (vectors README, anchoring note section 4)
        got = {"ok": False, "error": "policy_invalid"}
    return compare(d["expected"], got)


def check_registry_endpoint(d, raw):
    i = d["inputs"]
    if i.get("logged"):
        return ["a non empty `logged` list needs a log; not supported"]
    return compare(d["expected"], admission.admit_registry_endpoint(raw, i["now"], i["max_envelope_bytes"]))


def check_domain_binding(d, raw):
    return compare(d["expected"], domainmod.check_binding(d["inputs"]["fixture"]))


CHECKERS = {
    "checkpoint-hash": check_checkpoint_hash, "anchor-record": check_anchor_record,
    "chain-id": check_chain_id, "anchor-envelope": check_anchor_envelope,
    "anchor-media-type": check_verify, "anchor-not-supported": check_verify,
    "require-anchor": check_require_anchor, "registry-endpoint": check_registry_endpoint,
    "domain-binding": check_domain_binding,
    "identity": check_identity, "signing": check_signing, "encryption": check_encryption,
    "attestation": check_attestation, "srl": check_srl, "log": check_log,
    "verify-positive": check_verify, "verify-negative": check_verify,
    "chain-positive": check_verify, "chain-negative": check_verify,
    "atep-r-positive": check_verify, "atep-r-negative": check_verify,
    "retired-positive": check_verify, "retired-negative": check_verify,
    "successor-positive": check_verify, "successor-negative": check_verify,
    "srl-context": check_srl_context,
}


def run_vector(vdir, category, name):
    base = os.path.join(vdir, category, name)
    with open(base + ".expected.json") as f:
        d = json.load(f)
    with open(base + ".cbor", "rb") as f:
        raw = f.read()
    problems = []
    if hashlib.sha256(raw).hexdigest() != d["cbor_sha256"]:
        problems.append("cbor_sha256 in expected.json does not match file")
    try:
        problems += CHECKERS[category](d, raw)
    except Exception as e:  # a crash is a failure
        import traceback
        problems.append("exception: %s" % traceback.format_exc().strip().splitlines()[-1])
    return problems


def check(vdir, only=None, verbose=False, out=sys.stdout):
    with open(os.path.join(vdir, "manifest.json")) as f:
        manifest = json.load(f)
    stats = {}
    skipped = {}
    failures = []
    for v in manifest["vectors"]:
        cat, name = v["category"], v["name"]
        if only and only not in (cat, "%s/%s" % (cat, name)):
            continue
        if cat in SKIPS:
            skipped[cat] = skipped.get(cat, 0) + 1
            if verbose:
                out.write("SKIP %s/%s (%s)\n" % (cat, name, SKIPS[cat]))
            continue
        t = time.time()
        problems = []
        with open(os.path.join(vdir, cat, name + ".cbor"), "rb") as f:
            raw = f.read()
        if hashlib.sha256(raw).hexdigest() != v["cbor_sha256"]:
            problems.append("manifest cbor_sha256 mismatch")
        problems += run_vector(vdir, cat, name)
        ok = not problems
        s = stats.setdefault(cat, [0, 0])
        s[1] += 1
        if ok:
            s[0] += 1
        else:
            failures.append((cat, name, problems))
        if verbose or not ok:
            out.write("%s %s/%s (%.2fs)\n" % ("PASS" if ok else "FAIL", cat, name, time.time() - t))
            for p in problems:
                out.write("    %s\n" % p)
    out.write("\n")
    tp = tt = 0
    for cat in sorted(stats):
        out.write("%-18s %d/%d\n" % (cat, stats[cat][0], stats[cat][1]))
        tp += stats[cat][0]
        tt += stats[cat][1]
    out.write("%-18s %d/%d\n" % ("TOTAL", tp, tt))
    for cat in sorted(skipped):
        out.write("%-18s SKIPPED %d (%s)\n" % (cat, skipped[cat], SKIPS[cat]))
    if skipped:
        out.write("%-18s %d\n" % ("SKIPPED TOTAL", sum(skipped.values())))
    return len(failures) == 0


def main(argv):
    if len(argv) >= 2 and argv[0] == "check":
        only = None
        verbose = False
        rest = []
        for a in argv[2:]:
            if a == "-v":
                verbose = True
            else:
                only = a
        return 0 if check(argv[1], only, verbose) else 1
    sys.stderr.write("usage: python -m atep_py.vectors check <vectors-dir> [category[/name]] [-v]\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
