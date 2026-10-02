"""Pure Python Ed25519 (RFC 8032) with strict verification."""
import hashlib

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
I = pow(2, (P - 1) // 4, P)


def _inv(x):
    return pow(x, P - 2, P)


def _recover_x(y, sign):
    if y >= P:
        return None
    x2 = (y * y - 1) * _inv(D * y * y + 1) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * I % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


_GY = 4 * _inv(5) % P
_GX = _recover_x(_GY, 0)
G = (_GX, _GY, 1, _GX * _GY % P)
IDENT = (0, 1, 1, 0)


def _add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % P
    b = (p[1] + p[0]) * (q[1] + q[0]) % P
    c = 2 * p[3] * q[3] * D % P
    d = 2 * p[2] * q[2] % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(s, p):
    q = IDENT
    while s > 0:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


def _enc(p):
    zi = _inv(p[2])
    x = p[0] * zi % P
    y = p[1] * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _dec(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


def _h(m):
    return int.from_bytes(hashlib.sha512(m).digest(), "little")


def _expand(sk):
    h = hashlib.sha512(sk).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(sk):
    a, _ = _expand(sk)
    return _enc(_mul(a, G))


def sign(sk, msg):
    a, prefix = _expand(sk)
    A = _enc(_mul(a, G))
    r = _h(prefix + msg) % L
    R = _enc(_mul(r, G))
    k = _h(R + A + msg) % L
    S = (r + k * a) % L
    return R + S.to_bytes(32, "little")


def _small_order(p):
    q = p
    for _ in range(3):
        q = _add(q, q)
    return q[0] % P == 0  # [8]p is identity iff x == 0 and y == 1 (y==-1 impossible after 8x)


def verify_strict(pk, msg, sig):
    """Strict verification: canonical S, no small-order A or R."""
    if len(sig) != 64 or len(pk) != 32:
        return False
    A = _dec(pk)
    R = _dec(sig[:32])
    if A is None or R is None:
        return False
    S = int.from_bytes(sig[32:], "little")
    if S >= L:
        return False
    if _small_order(A) or _small_order(R):
        return False
    k = _h(sig[:32] + pk + msg) % L
    # [S]B - [k]A == R
    negA = ((-A[0]) % P, A[1], A[2], (-A[3]) % P)
    chk = _add(_mul(S, G), _mul(k, negA))
    return _enc(chk) == sig[:32]
