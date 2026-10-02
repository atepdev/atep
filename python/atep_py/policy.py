"""Step 9: trust policy evaluation, attestations, chain walking, ATEP-R command classes."""
from . import cbor, identity
from . import envelope as E
from .core import Reject, Context, verify_signed, _is_int
from . import srl as srlmod
from . import logs
from . import anchors

from .claims import (CLAIMS, R, ISSUER_AUTH, SUCCESSOR, MAX_LIFETIME, AUDIT_BACKED, expand_claim,
                     validate_attestation_payload, _bytes_n)


class AttInfo(object):
    pass


TRUST_MEMBERS = {"roots", "rules", "max_depth", "require_inclusion", "trusted_logs", "srl", "atep_r",
                 "follow_succession", "require_anchor"}


class TrustPolicy(object):
    def __init__(self, d):
        self.raw = d
        if not isinstance(d, dict) or not set(d) <= TRUST_MEMBERS:
            raise Reject(9, "policy_invalid")      # an unknown member is a configuration error
        try:
            self.roots = [identity.parse_agent_id(r) for r in d.get("roots", [])]
            self.rules = []
            for r in d.get("rules", []):
                root = identity.parse_agent_id(r["root"]) if r.get("root") else None
                self.rules.append({"claim": expand_claim(r["claim"]), "root": root,
                                   "max_age_days": r.get("max_age_days")})
            self.max_depth = d.get("max_depth", 5)
            self.require_inclusion = bool(d.get("require_inclusion", False))
            self.trusted_logs = [identity.parse_agent_id(x) for x in d.get("trusted_logs", [])]
            srl = d.get("srl", {})
            self.on_stale = srl.get("on_stale", "fail-closed")
            self.on_missing = srl.get("on_missing", "fail-open")
            self.atep_r = bool(d.get("atep_r", False))
            self.follow_succession = d.get("follow_succession", False)
            self.require_anchor = anchors.parse_require_anchor(d["require_anchor"]) \
                if "require_anchor" in d else []
        except (KeyError, ValueError, TypeError, AttributeError):
            raise Reject(9, "policy_invalid")
        if not isinstance(self.follow_succession, bool):
            raise Reject(9, "policy_invalid")
        if self.on_stale not in ("fail-closed", "fail-open") or self.on_missing not in ("fail-closed", "fail-open"):
            raise Reject(9, "policy_invalid")


class Evaluation(object):
    """State for one step 9 evaluation."""

    def __init__(self, signer, outer, inner, ctx, trust, pool_extra):
        self.signer = signer
        self.ctx = ctx.derive(check_replay=False, recipient=None, detached_payload=None,
                              atep_r=False, ignore_expiry=False)
        self.trust = trust
        self.receiver = ctx.recipient.agent_id if ctx.recipient is not None else None
        self.cache = {}
        self.checkpoints = []
        self.pool = []
        seen = set()

        def add(v):
            if not (isinstance(v, cbor.Tag) and v.tag == 98):
                return
            k = cbor.dumps(v)
            if k in seen:
                return
            seen.add(k)
            self.pool.append(v)
            nested = v.value[1].get(E.U_ATTS) if isinstance(v.value, list) and len(v.value) == 4 \
                and isinstance(v.value[1], dict) else None
            return nested
        queue = list(inner.unprot.get(E.U_ATTS, []) or []) if isinstance(inner.unprot.get(E.U_ATTS, []), list) else []
        while queue:
            v = queue.pop(0)
            nested = add(v)
            if isinstance(nested, list):
                queue.extend(nested)
        for raw in pool_extra:
            try:
                v = cbor.loads(raw)
            except cbor.CborError:
                continue
            nested = add(v)
            if isinstance(nested, list):
                for n in nested:
                    add(n)

    # -- helpers --

    @staticmethod
    def peek(v):
        """(subject, claim) from the payload of a pooled envelope, or None."""
        try:
            payload = v.value[2]
            if not isinstance(payload, bytes):
                return None
            p = cbor.loads(payload)
            if isinstance(p, dict):
                return p.get("subject"), p.get("claim")
        except Exception:
            pass
        return None

    def candidates(self, subject, claim):
        out = []
        for v in self.pool:
            pk = self.peek(v)
            if pk is not None and pk[0] == subject and pk[1] == claim:
                out.append(v)
        return out

    def verify_attestation(self, v, srl_mode, ignore_expiry):
        """Envelope steps 1-8, schema, issuer, lifetime, SRL, inclusion. Returns (AttInfo, warnings)."""
        key = (cbor.dumps(v), ignore_expiry)
        if key in self.cache:
            info = self.cache[key]
        else:
            ctx = self.ctx.derive(ignore_expiry=ignore_expiry)
            try:
                s = verify_signed(v, ctx, allow_encrypted=False)
            except Reject as r:
                raise Reject(9, "attestation_invalid", cause={"step": r.step, "error": r.error})
            if s.content_type != E.CT_ATTESTATION:
                raise Reject(9, "attestation_schema_invalid", detail="content type")
            try:
                p = cbor.loads(s.payload_bytes)
            except cbor.CborError:
                raise Reject(9, "attestation_schema_invalid", detail="payload not CBOR")
            validate_attestation_payload(p)
            if p["issuer"] != s.signer:
                raise Reject(9, "attestation_issuer_mismatch")
            if s.expires_at - s.issued_at > MAX_LIFETIME:
                raise Reject(9, "attestation_lifetime_exceeded")
            info = AttInfo()
            info.value = v
            info.signed = s
            info.payload = p
            info.id = p["id"]
            info.claim = p["claim"]
            info.subject = p["subject"]
            info.issuer = p["issuer"]
            info.issued_at = s.issued_at
            info.expires_at = s.expires_at
            self.cache[key] = info
        warnings = []
        self.check_srl(info, srl_mode, warnings)
        if self.trust.require_inclusion:
            cp = logs.check_inclusion(v, self.ctx, set(self.trust.trusted_logs))
            self.checkpoints.append(cp)
        return info, warnings

    def check_srl(self, info, srl_mode, warnings):
        on_stale, on_missing = srl_mode
        entry = self.ctx.srl_cache.get(info.issuer)
        who = identity.agent_id_text(info.issuer)
        if entry is None:
            if on_missing == "fail-closed":
                raise Reject(9, "srl_unavailable")
            w = "no SRL cached for issuer %s; revocation status unknown" % who
            if w not in warnings:
                warnings.append(w)
            return
        if self.ctx.now >= entry["next_update"]:
            if on_stale == "fail-closed":
                raise Reject(9, "srl_stale")
            w = srlmod.stale_warning(info.issuer, entry["next_update"])
            if w not in warnings:
                warnings.append(w)
        if info.id in entry["attestation_ids"]:
            raise Reject(9, "attestation_revoked")

    # -- chain --

    def authorize(self, issuer, needed, roots, chain, visited, srl_mode, ignore_expiry):
        """issuer must be authorized for every claim in `needed`.
        Returns (chain extension list of AttInfo, terminal root bytes, warnings)."""
        if issuer in roots:
            return [], issuer, []
        cands = self.candidates(issuer, ISSUER_AUTH)
        if not cands:
            raise Reject(9, "chain_broken")
        first_err = None
        for v in cands:
            try:
                info, warns = self.verify_attestation(v, srl_mode, ignore_expiry)
                if not set(needed) <= set(info.payload["data"]["claims"]):
                    raise Reject(9, "issuer_not_authorized")
                if info.issuer in visited or info.issuer == issuer:
                    raise Reject(9, "chain_cycle")
                if len(chain) + 1 > self.trust.max_depth:
                    raise Reject(9, "chain_depth_exceeded")
                ext, root, w2 = self.authorize(info.issuer, set(needed) | {ISSUER_AUTH}, roots,
                                               chain + [info], visited | {info.issuer},
                                               srl_mode, ignore_expiry)
                for w in w2:
                    if w not in warns:
                        warns.append(w)
                return [info] + ext, root, warns
            except Reject as r:
                if first_err is None:
                    first_err = r
        raise first_err

    def satisfy(self, claim, rule_root, max_age_days, srl_mode, ignore_expiry, data_check=None):
        """Satisfy one requirement. Returns a claim result dict plus warnings."""
        cands = self.candidates(self.signer, claim)
        if not cands:
            if self.trust.follow_succession:
                return self.satisfy_by_succession(claim, rule_root, max_age_days, srl_mode,
                                                  ignore_expiry, data_check)
            raise Reject(9, "claim_missing")
        roots = [rule_root] if rule_root is not None else list(self.trust.roots)
        first_err = None
        for v in cands:
            try:
                info, warns = self.verify_attestation(v, srl_mode, ignore_expiry)
                if max_age_days is not None and self.ctx.now - info.issued_at > max_age_days * 86400:
                    raise Reject(9, "claim_too_old")
                if data_check is not None and not data_check(info.payload["data"]):
                    raise Reject(9, "claim_data_mismatch")
                ext, root, w2 = self.authorize(info.issuer, {claim}, roots, [info],
                                               {info.issuer}, srl_mode, ignore_expiry)
                for w in w2:
                    if w not in warns:
                        warns.append(w)
                chain = [info] + ext
                res = {
                    "claim": claim,
                    "issuer": identity.agent_id_text(info.issuer),
                    "root": identity.agent_id_text(root),
                    "expires_at": min(a.expires_at for a in chain),
                    "chain": [{"id": a.id.hex(), "claim": a.claim,
                               "subject": identity.agent_id_text(a.subject),
                               "issuer": identity.agent_id_text(a.issuer),
                               "issued_at": a.issued_at, "expires_at": a.expires_at} for a in chain],
                }
                return res, warns
            except Reject as r:
                if first_err is None:
                    first_err = r
        raise first_err


    def satisfy_by_succession(self, claim, rule_root, max_age_days, srl_mode, ignore_expiry, data_check):
        """One hop of succession (section 7). Fails with claim_missing when no pair passes."""
        roots = [rule_root] if rule_root is not None else list(self.trust.roots)
        warnings = []

        def note(ws):
            for w in ws:
                if w not in warnings:
                    warnings.append(w)
        for sv in self.candidates(self.signer, SUCCESSOR):
            try:
                sinfo, sw = self.verify_attestation(sv, srl_mode, ignore_expiry)
            except Reject as r:
                continue
            note(sw)
            old = sinfo.issuer
            for cv in self.candidates(old, claim):
                try:
                    info, cw = self.verify_attestation(cv, srl_mode, ignore_expiry)
                    note(cw)
                    if max_age_days is not None and self.ctx.now - info.issued_at > max_age_days * 86400:
                        continue
                    if data_check is not None and not data_check(info.payload["data"]):
                        continue
                    ext, root, aw = self.authorize(info.issuer, {claim}, roots, [info, sinfo],
                                                   {info.issuer}, srl_mode, ignore_expiry)
                except Reject as r:
                    continue
                note(aw)
                chain = [info, sinfo] + ext
                res = {
                    "claim": claim,
                    "issuer": identity.agent_id_text(info.issuer),
                    "root": identity.agent_id_text(root),
                    "expires_at": min(a.expires_at for a in chain),
                    "chain": [self.link(a) for a in chain],
                }
                return res, warnings
        raise Reject(9, "claim_missing")

    @staticmethod
    def link(a):
        return {"id": a.id.hex(), "claim": a.claim, "subject": identity.agent_id_text(a.subject),
                "issuer": identity.agent_id_text(a.issuer), "issued_at": a.issued_at,
                "expires_at": a.expires_at}


def _estop(payload):
    try:
        p = cbor.loads(payload)
    except cbor.CborError:
        return False
    return isinstance(p, dict) and p.get("command") == "e-stop"


def class_requirements(cls, payload, receiver):
    """Returns (alternatives, srl_mode, ignore_expiry). Each alternative is a list of
    (claim uri, data_check or None)."""
    fm = (R + "fleet-member", None)
    open_mode = ("fail-open", "fail-open")
    closed = ("fail-closed", "fail-closed")
    if cls == "telemetry" or cls == "coordination":
        return [[fm]], open_mode, False
    if cls == "sensor":
        return [[fm, (R + "sensor-source", None)]], open_mode, False
    if cls == "motion":
        def peers_ok(data):
            peers = data.get("peers")
            return isinstance(peers, list) and receiver is not None and receiver in peers
        return [[(R + "fleet-controller", None)], [fm, (R + "peer-motion", peers_ok)]], closed, False
    if cls == "actuation":
        return [[(R + "fleet-controller", None), (R + "safety-certified", None)]], closed, False
    if cls == "safety":
        if _estop(payload):
            return [[(R + "safety-authority", None)], [fm, (R + "safety-certified", None)]], open_mode, True
        return [[(R + "safety-authority", None)]], closed, False
    if cls == "maintenance":
        return [[(R + "maintenance-authority", None)]], closed, False
    raise Reject(1, "unknown_command_class")


def evaluate(signer_id, outer, inner, ctx, trust_dict, extra_attestations):
    """Returns (claims, checkpoint or None, warnings)."""
    trust = TrustPolicy(trust_dict)
    if trust.require_anchor:
        # Draft 05 section 7: rules cannot be evaluated here, so fail closed before any other rule
        raise Reject(9, "anchor_not_supported")
    ev = Evaluation(signer_id, outer, inner, ctx, trust, extra_attestations)
    claims = []
    warnings = []

    def merge(ws):
        for w in ws:
            if w not in warnings:
                warnings.append(w)

    base_mode = (trust.on_stale, trust.on_missing)
    for rule in trust.rules:
        res, ws = ev.satisfy(rule["claim"], rule["root"], rule["max_age_days"], base_mode, False)
        claims.append(res)
        merge(ws)
    if trust.atep_r:
        alts, mode, ign = class_requirements(inner.command_class, inner.payload_bytes, ev.receiver)
        best = None
        best_n = -1
        for alt in alts:
            got = []
            gw = []
            err = None
            for claim, chk in alt:
                try:
                    res, ws = ev.satisfy(claim, None, None, mode, ign, chk)
                except Reject as r:
                    err = r
                    break
                got.append(res)
                for w in ws:
                    if w not in gw:
                        gw.append(w)
            if err is None:
                best = (got, gw)
                best_n = None
                break
            if len(got) > best_n:
                best_n = len(got)
                best_err = err
        if best is None:
            raise best_err
        claims.extend(best[0])
        merge(best[1])
    cp = None
    for c in ev.checkpoints:
        if cp is None or c["timestamp"] > cp["timestamp"]:
            cp = c
    return claims, cp, warnings
