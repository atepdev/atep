"""Pure Python AES-256-GCM."""
import hmac


def _build():
    sbox = [0] * 256
    p = q = 1
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ ((q << 1) | (q >> 7)) & 0xFF ^ ((q << 2) | (q >> 6)) & 0xFF ^ ((q << 3) | (q >> 5)) & 0xFF ^ ((q << 4) | (q >> 4)) & 0xFF
        sbox[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox


SBOX = _build()


def _xt(a):
    a <<= 1
    return (a ^ 0x11B) if a & 0x100 else a


def _expand_key(key):
    nk = len(key) // 4
    nr = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rc = 1
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= rc
            rc = _xt(rc)
        elif nk > 6 and i % nk == 4:
            t = [SBOX[b] for b in t]
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    rks = []
    for r in range(nr + 1):
        rk = []
        for c in range(4):
            rk += w[4 * r + c]
        rks.append(rk)
    return rks


def _encrypt_block(rks, block):
    s = [block[i] ^ rks[0][i] for i in range(16)]
    nr = len(rks) - 1
    for r in range(1, nr + 1):
        s = [SBOX[b] for b in s]
        # shift rows (column-major state)
        s = [s[0], s[5], s[10], s[15], s[4], s[9], s[14], s[3],
             s[8], s[13], s[2], s[7], s[12], s[1], s[6], s[11]]
        if r != nr:
            o = []
            for c in range(4):
                a0, a1, a2, a3 = s[4 * c:4 * c + 4]
                t = a0 ^ a1 ^ a2 ^ a3
                o += [a0 ^ t ^ _xt(a0 ^ a1), a1 ^ t ^ _xt(a1 ^ a2),
                      a2 ^ t ^ _xt(a2 ^ a3), a3 ^ t ^ _xt(a3 ^ a0)]
            s = o
        rk = rks[r]
        s = [s[i] ^ rk[i] for i in range(16)]
    return bytes(s)


_R = 0xE1 << 120


def _gmul(x, y):
    z = 0
    v = y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        v = (v >> 1) ^ _R if v & 1 else v >> 1
    return z


def _ghash(h, aad, ct):
    def blocks(b):
        for i in range(0, len(b), 16):
            c = b[i:i + 16]
            yield int.from_bytes(c + b"\x00" * (16 - len(c)), "big")
    y = 0
    for blk in blocks(aad):
        y = _gmul(y ^ blk, h)
    for blk in blocks(ct):
        y = _gmul(y ^ blk, h)
    ln = ((len(aad) * 8) << 64) | (len(ct) * 8)
    return _gmul(y ^ ln, h)


def _ctr(rks, j0, data):
    out = bytearray()
    ctr = int.from_bytes(j0, "big")
    for i in range(0, len(data), 16):
        ctr = (ctr & ~0xFFFFFFFF) | (((ctr & 0xFFFFFFFF) + 1) & 0xFFFFFFFF)
        ks = _encrypt_block(rks, ctr.to_bytes(16, "big"))
        chunk = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(chunk, ks))
    return bytes(out)


def _setup(key, iv):
    if len(key) != 32 or len(iv) != 12:
        raise ValueError("bad key or iv length")
    rks = _expand_key(key)
    h = int.from_bytes(_encrypt_block(rks, b"\x00" * 16), "big")
    j0 = iv + b"\x00\x00\x00\x01"
    return rks, h, j0


def encrypt(key, iv, plaintext, aad):
    rks, h, j0 = _setup(key, iv)
    ct = _ctr(rks, j0, plaintext)
    s = _ghash(h, aad, ct)
    tag = (s ^ int.from_bytes(_encrypt_block(rks, j0), "big")).to_bytes(16, "big")
    return ct + tag


def decrypt(key, iv, data, aad):
    """Returns plaintext or None on authentication failure."""
    if len(data) < 16:
        return None
    ct, tag = data[:-16], data[-16:]
    rks, h, j0 = _setup(key, iv)
    s = _ghash(h, aad, ct)
    exp = (s ^ int.from_bytes(_encrypt_block(rks, j0), "big")).to_bytes(16, "big")
    if not hmac.compare_digest(exp, tag):
        return None
    return _ctr(rks, j0, ct)
