"""Rejection type shared by all verification modules."""


class Reject(Exception):
    def __init__(self, step, error, cause=None, detail=None):
        Exception.__init__(self, "step %s: %s%s" % (step, error, " (%s)" % detail if detail else ""))
        self.step = step
        self.error = error
        self.cause = cause
        self.detail = detail

    def as_dict(self):
        d = {"ok": False, "step": self.step, "error": self.error}
        if self.cause is not None:
            d["cause"] = self.cause
        return d
