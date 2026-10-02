"""Pure Python ML-DSA-65 (FIPS 204): KeyGen_internal, Sign (Alg 2, pure, empty ctx), Verify (Alg 3)."""
import hashlib

Q = 8380417
N = 256
K = 6
L = 5
ETA = 4
TAU = 49
GAMMA1 = 1 << 19
GAMMA2 = (Q - 1) // 32
BETA = TAU * ETA
OMEGA = 55
LAMBDA = 192
D = 13
CT_LEN = LAMBDA // 4
PK_LEN = 32 + K * 320
SIG_LEN = CT_LEN + L * 640 + OMEGA + K

ZETA = 1753


def _brv8(i):
    return int("{:08b}".format(i)[::-1], 2)


ZETAS = [pow(ZETA, _brv8(i), Q) for i in range(256)]
F_INV = pow(256, Q - 2, Q)


def ntt(a):
    w = list(a)
    m = 0
    ln = 128
    while ln >= 1:
        for start in range(0, 256, 2 * ln):
            m += 1
            z = ZETAS[m]
            for j in range(start, start + ln):
                t = z * w[j + ln] % Q
                w[j + ln] = (w[j] - t) % Q
                w[j] = (w[j] + t) % Q
        ln >>= 1
    return w


def intt(a):
    w = list(a)
    m = 256
    ln = 1
    while ln < 256:
        for start in range(0, 256, 2 * ln):
            m -= 1
            z = -ZETAS[m]
            for j in range(start, start + ln):
                t = w[j]
                w[j] = (t + w[j + ln]) % Q
                w[j + ln] = z * (t - w[j + ln]) % Q
        ln <<= 1
    return [x * F_INV % Q for x in w]


def _mul(a, b):
    return [x * y % Q for x, y in zip(a, b)]


def _add(a, b):
    return [(x + y) % Q for x, y in zip(a, b)]


def _sub(a, b):
    return [(x - y) % Q for x, y in zip(a, b)]


def shake128(data, n):
    return hashlib.shake_128(data).digest(n)


def shake256(data, n):
    return hashlib.shake_256(data).digest(n)


def _rej_ntt_poly(seed):
    # generous stream; extend if needed
    n = 840
    while True:
        s = shake128(seed, n)
        out = []
        i = 0
        while len(out) < 256 and i + 3 <= len(s):
            z = s[i] | (s[i + 1] << 8) | ((s[i + 2] & 0x7F) << 16)
            i += 3
            if z < Q:
                out.append(z)
        if len(out) == 256:
            return out
        n *= 2


def expand_a(rho):
    return [[_rej_ntt_poly(rho + bytes([s, r])) for s in range(L)] for r in range(K)]


def _rej_bounded_poly(seed):
    n = 272
    while True:
        s = shake256(seed, n)
        out = []
        for b in s:
            for z in (b & 15, b >> 4):
                if z < 9 and len(out) < 256:
                    out.append(ETA - z)
            if len(out) == 256:
                return out
        n *= 2


def expand_s(rho):
    s1 = [_rej_bounded_poly(rho + r.to_bytes(2, "little")) for r in range(L)]
    s2 = [_rej_bounded_poly(rho + (r + L).to_bytes(2, "little")) for r in range(K)]
    return s1, s2


def expand_mask(rho, mu):
    y = []
    for r in range(L):
        v = shake256(rho + (mu + r).to_bytes(2, "little"), 640)
        vals = _unpack(v, 20, 256)
        y.append([GAMMA1 - x for x in vals])
    return y


def _unpack(b, bits, count):
    x = int.from_bytes(b, "little")
    mask = (1 << bits) - 1
    return [(x >> (i * bits)) & mask for i in range(count)]


def _pack(vals, bits):
    x = 0
    for i, v in enumerate(vals):
        x |= v << (i * bits)
    return x.to_bytes(len(vals) * bits // 8, "little")


def sample_in_ball(seed):
    s = shake256(seed, 8 + 2048)
    signs = int.from_bytes(s[:8], "little")
    pos = 8
    c = [0] * 256
    for i in range(256 - TAU, 256):
        while True:
            if pos >= len(s):
                raise ValueError("sample_in_ball exhausted")
            j = s[pos]
            pos += 1
            if j <= i:
                break
        c[i] = c[j]
        c[j] = 1 - 2 * (signs & 1)
        signs >>= 1
    return c


def _modpm(r, a):
    r %= a
    if r > a // 2:
        r -= a
    return r


def power2round(r):
    r %= Q
    r0 = _modpm(r, 1 << D)
    return (r - r0) >> D, r0


def decompose(r):
    r %= Q
    r0 = _modpm(r, 2 * GAMMA2)
    if r - r0 == Q - 1:
        return 0, r0 - 1
    return (r - r0) // (2 * GAMMA2), r0


def high_bits(r):
    return decompose(r)[0]


def low_bits(r):
    return decompose(r)[1]


def make_hint(z, r):
    return 1 if high_bits(r) != high_bits(r + z) else 0


def use_hint(h, r):
    m = (Q - 1) // (2 * GAMMA2)
    r1, r0 = decompose(r)
    if h == 1:
        return (r1 + 1) % m if r0 > 0 else (r1 - 1) % m
    return r1


def _mat_vec(A, v_hat):
    out = []
    for row in A:
        acc = [0] * 256
        for a, b in zip(row, v_hat):
            acc = [(x + y * z) % Q for x, y, z in zip(acc, a, b)]
        out.append(acc)
    return out


def _inf_norm_ge(poly_vec, bound):
    for p in poly_vec:
        for c in p:
            c %= Q
            if c > Q // 2:
                c = Q - c
            if c >= bound:
                return True
    return False


def _centered(c):
    c %= Q
    return c - Q if c > Q // 2 else c


def keygen_internal(xi):
    seed = shake256(xi + bytes([K, L]), 128)
    rho, rho2, key = seed[:32], seed[32:96], seed[96:]
    A = expand_a(rho)
    s1, s2 = expand_s(rho2)
    s1h = [ntt([c % Q for c in p]) for p in s1]
    prod = _mat_vec(A, s1h)
    t = [_add(intt(prod[i]), [c % Q for c in s2[i]]) for i in range(K)]
    t1, t0 = [], []
    for p in t:
        a, b = zip(*[power2round(c) for c in p])
        t1.append(list(a))
        t0.append(list(b))
    pk = rho + b"".join(_pack(p, 10) for p in t1)
    tr = shake256(pk, 64)
    sk = (rho, key, tr, s1, s2, t0)
    return pk, sk


def public_key(xi):
    return keygen_internal(xi)[0]


def sign(sk, message, rnd=bytes(32), ctx=b""):
    """ML-DSA.Sign (pure), deterministic when rnd is 32 zero bytes."""
    rho, key, tr, s1, s2, t0 = sk
    A = expand_a(rho)
    mp = bytes([0, len(ctx)]) + ctx + message
    mu = shake256(tr + mp, 64)
    rho2 = shake256(key + rnd + mu, 64)
    s1h = [ntt([c % Q for c in p]) for p in s1]
    s2h = [ntt([c % Q for c in p]) for p in s2]
    t0h = [ntt([c % Q for c in p]) for p in t0]
    kappa = 0
    while True:
        y = expand_mask(rho2, kappa)
        yh = [ntt([c % Q for c in p]) for p in y]
        w = [intt(p) for p in _mat_vec(A, yh)]
        w1 = [[high_bits(c) for c in p] for p in w]
        w1b = b"".join(_pack(p, 4) for p in w1)
        ct = shake256(mu + w1b, CT_LEN)
        c = sample_in_ball(ct)
        ch = ntt([x % Q for x in c])
        cs1 = [intt(_mul(ch, p)) for p in s1h]
        cs2 = [intt(_mul(ch, p)) for p in s2h]
        z = [_add([x % Q for x in y[i]], cs1[i]) for i in range(L)]
        r0 = [[low_bits(a - b) for a, b in zip(w[i], cs2[i])] for i in range(K)]
        kappa += L
        if _inf_norm_ge(z, GAMMA1 - BETA):
            continue
        if any(abs(v) >= GAMMA2 - BETA for p in r0 for v in p):
            continue
        ct0 = [intt(_mul(ch, p)) for p in t0h]
        if _inf_norm_ge(ct0, GAMMA2):
            continue
        h = []
        ones = 0
        for i in range(K):
            row = []
            for j in range(256):
                wc = (w[i][j] - cs2[i][j] + ct0[i][j]) % Q
                # MakeHint(-ct0, w - cs2 + ct0)
                hh = make_hint((-ct0[i][j]) % Q, wc)
                row.append(hh)
                ones += hh
            h.append(row)
        if ones > OMEGA:
            continue
        zb = b"".join(_pack([(GAMMA1 - _centered(c_)) for c_ in p], 20) for p in z)
        return ct + zb + _hint_pack(h)


def _hint_pack(h):
    y = bytearray(OMEGA + K)
    idx = 0
    for i in range(K):
        for j in range(256):
            if h[i][j]:
                y[idx] = j
                idx += 1
        y[OMEGA + i] = idx
    return bytes(y)


def _hint_unpack(y):
    h = [[0] * 256 for _ in range(K)]
    idx = 0
    for i in range(K):
        end = y[OMEGA + i]
        if end < idx or end > OMEGA:
            return None
        first = idx
        while idx < end:
            if idx > first and y[idx - 1] >= y[idx]:
                return None
            h[i][y[idx]] = 1
            idx += 1
    for i in range(idx, OMEGA):
        if y[i] != 0:
            return None
    return h


def verify(pk, message, sig, ctx=b""):
    if len(pk) != PK_LEN or len(sig) != SIG_LEN:
        return False
    rho = pk[:32]
    t1 = [_unpack(pk[32 + 320 * i:32 + 320 * (i + 1)], 10, 256) for i in range(K)]
    ct = sig[:CT_LEN]
    zb = sig[CT_LEN:CT_LEN + L * 640]
    z = [[GAMMA1 - x for x in _unpack(zb[640 * i:640 * (i + 1)], 20, 256)] for i in range(L)]
    h = _hint_unpack(sig[CT_LEN + L * 640:])
    if h is None:
        return False
    if any(abs(v) >= GAMMA1 - BETA for p in z for v in p):
        return False
    A = expand_a(rho)
    tr = shake256(pk, 64)
    mp = bytes([0, len(ctx)]) + ctx + message
    mu = shake256(tr + mp, 64)
    c = sample_in_ball(ct)
    ch = ntt([x % Q for x in c])
    zh = [ntt([x % Q for x in p]) for p in z]
    az = _mat_vec(A, zh)
    t1h = [ntt([(x << D) % Q for x in p]) for p in t1]
    wp = []
    for i in range(K):
        wp.append(intt(_sub(az[i], _mul(ch, t1h[i]))))
    w1 = [[use_hint(h[i][j], wp[i][j]) for j in range(256)] for i in range(K)]
    w1b = b"".join(_pack(p, 4) for p in w1)
    return shake256(mu + w1b, CT_LEN) == ct
