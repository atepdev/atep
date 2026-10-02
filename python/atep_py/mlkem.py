"""Pure Python ML-KEM-768 (FIPS 203): KeyGen_internal, Encaps_internal, Decaps."""
import hashlib

Q = 3329
K = 3
ETA1 = 2
ETA2 = 2
DU = 10
DV = 4
EK_LEN = 384 * K + 32
CT_LEN = 32 * (DU * K + DV)


def _brv7(i):
    return int("{:07b}".format(i)[::-1], 2)


ZETAS = [pow(17, _brv7(i), Q) for i in range(128)]
GAMMAS = [pow(17, 2 * _brv7(i) + 1, Q) for i in range(128)]


def ntt(f):
    f = list(f)
    i = 1
    ln = 128
    while ln >= 2:
        for start in range(0, 256, 2 * ln):
            z = ZETAS[i]
            i += 1
            for j in range(start, start + ln):
                t = z * f[j + ln] % Q
                f[j + ln] = (f[j] - t) % Q
                f[j] = (f[j] + t) % Q
        ln >>= 1
    return f


def intt(f):
    f = list(f)
    i = 127
    ln = 2
    while ln <= 128:
        for start in range(0, 256, 2 * ln):
            z = ZETAS[i]
            i -= 1
            for j in range(start, start + ln):
                t = f[j]
                f[j] = (t + f[j + ln]) % Q
                f[j + ln] = z * (f[j + ln] - t) % Q
        ln <<= 1
    return [x * 3303 % Q for x in f]


def mul_ntt(f, g):
    h = [0] * 256
    for i in range(128):
        a0, a1 = f[2 * i], f[2 * i + 1]
        b0, b1 = g[2 * i], g[2 * i + 1]
        h[2 * i] = (a0 * b0 + a1 * b1 % Q * GAMMAS[i]) % Q
        h[2 * i + 1] = (a0 * b1 + a1 * b0) % Q
    return h


def _add(a, b):
    return [(x + y) % Q for x, y in zip(a, b)]


def _sub(a, b):
    return [(x - y) % Q for x, y in zip(a, b)]


def _sample_ntt(seed):
    n = 672
    while True:
        s = hashlib.shake_128(seed).digest(n)
        out = []
        i = 0
        while len(out) < 256 and i + 3 <= len(s):
            d1 = s[i] + 256 * (s[i + 1] & 15)
            d2 = (s[i + 1] >> 4) + 16 * s[i + 2]
            i += 3
            if d1 < Q:
                out.append(d1)
            if d2 < Q and len(out) < 256:
                out.append(d2)
        if len(out) == 256:
            return out
        n *= 2


def _cbd(b, eta):
    x = int.from_bytes(b, "little")
    out = []
    mask = (1 << eta) - 1
    for i in range(256):
        a = (x >> (2 * i * eta)) & mask
        c = (x >> ((2 * i + 1) * eta)) & mask
        out.append((bin(a).count("1") - bin(c).count("1")) % Q)
    return out


def _prf(eta, s, b):
    return hashlib.shake_256(s + bytes([b])).digest(64 * eta)


def _enc(vals, d):
    x = 0
    for i, v in enumerate(vals):
        x |= v << (i * d)
    return x.to_bytes(32 * d, "little")


def _dec(b, d):
    x = int.from_bytes(b, "little")
    m = (1 << d) - 1
    vals = [(x >> (i * d)) & m for i in range(256)]
    if d == 12:
        vals = [v % Q for v in vals]
    return vals


def _compress(vals, d):
    return [(((v << d) + Q // 2) // Q) % (1 << d) for v in vals]


def _decompress(vals, d):
    return [(Q * v + (1 << (d - 1))) >> d for v in vals]


def _gen_a(rho):
    return [[_sample_ntt(rho + bytes([j, i])) for j in range(K)] for i in range(K)]


def _g(b):
    d = hashlib.sha3_512(b).digest()
    return d[:32], d[32:]


def keygen_internal(d, z):
    rho, sigma = _g(d + bytes([K]))
    A = _gen_a(rho)
    n = 0
    s = []
    for i in range(K):
        s.append(_cbd(_prf(ETA1, sigma, n), ETA1))
        n += 1
    e = []
    for i in range(K):
        e.append(_cbd(_prf(ETA1, sigma, n), ETA1))
        n += 1
    sh = [ntt(p) for p in s]
    eh = [ntt(p) for p in e]
    th = []
    for i in range(K):
        acc = eh[i]
        for j in range(K):
            acc = _add(acc, mul_ntt(A[i][j], sh[j]))
        th.append(acc)
    ek = b"".join(_enc(p, 12) for p in th) + rho
    dkpke = b"".join(_enc(p, 12) for p in sh)
    dk = dkpke + ek + hashlib.sha3_256(ek).digest() + z
    return ek, dk


def keygen_from_seed(seed64):
    return keygen_internal(seed64[:32], seed64[32:])


def _pke_encrypt(ek, m, r):
    th = [_dec(ek[384 * i:384 * (i + 1)], 12) for i in range(K)]
    rho = ek[384 * K:]
    A = _gen_a(rho)
    n = 0
    y = []
    for i in range(K):
        y.append(_cbd(_prf(ETA1, r, n), ETA1))
        n += 1
    e1 = []
    for i in range(K):
        e1.append(_cbd(_prf(ETA2, r, n), ETA2))
        n += 1
    e2 = _cbd(_prf(ETA2, r, n), ETA2)
    yh = [ntt(p) for p in y]
    u = []
    for i in range(K):
        acc = [0] * 256
        for j in range(K):
            acc = _add(acc, mul_ntt(A[j][i], yh[j]))
        u.append(_add(intt(acc), e1[i]))
    mu = _decompress(_dec(m, 1), 1)
    acc = [0] * 256
    for j in range(K):
        acc = _add(acc, mul_ntt(th[j], yh[j]))
    v = _add(_add(intt(acc), e2), mu)
    c1 = b"".join(_enc(_compress(p, DU), DU) for p in u)
    c2 = _enc(_compress(v, DV), DV)
    return c1 + c2


def _pke_decrypt(dkpke, c):
    sh = [_dec(dkpke[384 * i:384 * (i + 1)], 12) for i in range(K)]
    u = [_decompress(_dec(c[32 * DU * i:32 * DU * (i + 1)], DU), DU) for i in range(K)]
    v = _decompress(_dec(c[32 * DU * K:], DV), DV)
    acc = [0] * 256
    for j in range(K):
        acc = _add(acc, mul_ntt(sh[j], ntt(u[j])))
    w = _sub(v, intt(acc))
    return _enc(_compress(w, 1), 1)


def encaps_internal(ek, m):
    if len(ek) != EK_LEN:
        raise ValueError("bad ek length")
    k, r = _g(m + hashlib.sha3_256(ek).digest())
    return k, _pke_encrypt(ek, m, r)


def decaps(dk, c):
    if len(c) != CT_LEN or len(dk) != 768 * K + 96:
        raise ValueError("bad length")
    dkpke = dk[:384 * K]
    ek = dk[384 * K:768 * K + 32]
    h = dk[768 * K + 32:768 * K + 64]
    z = dk[768 * K + 64:]
    m = _pke_decrypt(dkpke, c)
    k, r = _g(m + h)
    kbar = hashlib.shake_256(z + c).digest(32)
    c2 = _pke_encrypt(ek, m, r)
    return k if c2 == c else kbar
