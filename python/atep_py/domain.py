"""Domain records and the binding check (spec section 4 "Domain records", section 7 "Checking a domain binding").

Pure functions over what a fetcher answered; there is no network code. `check_binding(fixture)` takes the
fixture format of the `domain-binding` vectors."""
import json
import re

from . import identity

MAX_DOC_BYTES = 65536
MAX_AGENTS = 1024
MAX_TXT_OCTETS = 1024
MIN_TXT_RECORDS = 16
_LABEL = re.compile(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?")


def valid_domain(d):
    if not (isinstance(d, str) and 1 <= len(d) <= 253):
        return False
    return all(len(l) <= 63 and _LABEL.fullmatch(l) for l in d.split("."))


def _agent(text):
    try:
        return identity.parse_agent_id(text)
    except (ValueError, AttributeError):
        return None


def _no_constant(c):
    raise ValueError(c)


def _body_text(ans):
    f = ans.get("body_filler")
    if f is not None:
        fill_n = f["total_bytes"] - len(f["prefix"].encode("utf-8")) - len(f["suffix"].encode("utf-8"))
        return f["prefix"] + f["fill"] * (fill_n // max(len(f["fill"].encode("utf-8")), 1)) + f["suffix"]
    return ans.get("body", "")


def well_known_state(domain, agent_id, ans):
    """State of the well-known source from the fetcher's answer (None: the document does not exist)."""
    if ans is None:
        return "absent"
    if "unavailable" in ans:
        return "unavailable"
    status = ans.get("status")
    if status == 429 or (isinstance(status, int) and 500 <= status <= 599):
        return "unavailable"
    if status in (404, 410):
        return "absent"
    if status != 200:
        return "invalid"
    if not str(ans.get("final_url")).startswith("https://%s/" % domain):
        return "invalid"
    ct = ans.get("content_type")
    if not isinstance(ct, str) or ct.split(";", 1)[0].strip().lower() != "application/json":
        return "invalid"
    body = _body_text(ans)
    raw = body.encode("utf-8")
    if len(raw) > MAX_DOC_BYTES:
        return "invalid"
    try:
        doc = json.loads(raw.decode("utf-8"), parse_constant=_no_constant)
    except ValueError:
        return "invalid"
    if not isinstance(doc, dict):
        return "invalid"
    v = doc.get("version")
    if not (isinstance(v, int) and not isinstance(v, bool) and v == 1):
        return "invalid"
    agents = doc.get("agents")
    if not isinstance(agents, list):
        return "invalid"
    if "domain" in doc and doc["domain"] != domain:
        return "invalid"
    want = _agent(agent_id)
    for e in agents[:MAX_AGENTS]:
        if isinstance(e, str) and want is not None and _agent(e) == want:
            return "listed"
    return "not-listed"


def txt_record_text(rec):
    return "".join(rec) if isinstance(rec, list) else rec


def txt_authorized_set(records):
    """(counting records exist, set of Agent IDs) from the TXT record texts."""
    counted = False
    ids = set()
    for rec in records[:max(MIN_TXT_RECORDS, len(records))]:
        t = txt_record_text(rec)
        if not isinstance(t, str) or any(ord(c) > 127 for c in t) or len(t) > MAX_TXT_OCTETS:
            continue
        if not (t.startswith("v=atep1") and (len(t) == 7 or t[7] == " ")):
            continue
        counted = True
        for term in t[7:].split(" "):
            if term.startswith("id="):
                a = _agent(term[3:])
                if a is not None:
                    ids.add(a)
    return counted, ids


def dns_state(agent_id, ans, require_dnssec=False):
    if ans is None:
        return "absent"
    if "unavailable" in ans:
        return "unavailable"
    if require_dnssec and not ans.get("dnssec_validated"):
        return "unavailable"        # fail closed: an unvalidated answer is treated as not readable
    counted, ids = txt_authorized_set(ans.get("records") or [])
    if not counted:
        return "absent"
    want = _agent(agent_id)
    return "listed" if want is not None and want in ids else "not-listed"


def outcome(a, b, require_both=False):
    """Section 7, 'Checking a domain binding', step 3, with a the well-known state and b the DNS state."""
    if require_both:
        if a == b == "listed":
            return "bound"
        if a in ("absent", "invalid", "not-listed") or b in ("absent", "invalid", "not-listed"):
            return "not-bound"
        return "indeterminate"
    if (a == "listed" and b != "not-listed") or (b == "listed" and a != "not-listed"):
        return "bound"
    if "listed" in (a, b):
        return "not-bound"          # one lists, the other is valid and omits the Agent ID
    if "unavailable" in (a, b):
        return "indeterminate"
    return "not-bound"


def check_binding(fixture):
    domain = fixture["domain"]
    opts = fixture.get("options", {})
    if not valid_domain(domain):
        return {"well_known": "not-read", "dns": "not-read", "outcome": "not-bound",
                "queried": {"well_known": [], "txt": []}}
    name = "_atep." + domain
    a = well_known_state(domain, fixture["agent_id"], fixture.get("well_known", {}).get(domain))
    b = dns_state(fixture["agent_id"], fixture.get("txt", {}).get(name), bool(opts.get("require_dnssec")))
    return {"well_known": a, "dns": b, "outcome": outcome(a, b, bool(opts.get("require_both"))),
            "queried": {"well_known": [domain], "txt": [name]}}
