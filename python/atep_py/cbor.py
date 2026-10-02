"""Strict deterministic CBOR (RFC 8949 section 4.2.1) for ATEP.

Only the types ATEP uses: unsigned/negative ints (64 bit signed range plus
the CBOR negative range check below), byte strings, text strings, arrays,
maps, booleans, null, and tags 96 and 98.
"""
import struct


class CborError(Exception):
    pass


class Tag(object):
    __slots__ = ("tag", "value")

    def __init__(self, tag, value):
        self.tag = tag
        self.value = value

    def __eq__(self, other):
        return isinstance(other, Tag) and self.tag == other.tag and self.value == other.value

    def __repr__(self):
        return "Tag(%r, %r)" % (self.tag, self.value)


MAX_DEPTH = 32
ALLOWED_TAGS = (96, 98)
INT_MIN = -(1 << 63)
INT_MAX = (1 << 63) - 1


def _head(major, n):
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 256:
        return bytes([(major << 5) | 24, n])
    if n < 65536:
        return bytes([(major << 5) | 25]) + struct.pack(">H", n)
    if n < (1 << 32):
        return bytes([(major << 5) | 26]) + struct.pack(">I", n)
    return bytes([(major << 5) | 27]) + struct.pack(">Q", n)


def dumps(v):
    if v is None:
        return b"\xf6"
    if v is True:
        return b"\xf5"
    if v is False:
        return b"\xf4"
    if isinstance(v, int):
        if v < INT_MIN or v > INT_MAX:
            raise CborError("integer out of range")
        if v >= 0:
            return _head(0, v)
        return _head(1, -1 - v)
    if isinstance(v, (bytes, bytearray)):
        return _head(2, len(v)) + bytes(v)
    if isinstance(v, str):
        b = v.encode("utf-8")
        return _head(3, len(b)) + b
    if isinstance(v, (list, tuple)):
        return _head(4, len(v)) + b"".join(dumps(x) for x in v)
    if isinstance(v, dict):
        items = sorted((dumps(k), dumps(x)) for k, x in v.items())
        for i in range(1, len(items)):
            if items[i][0] == items[i - 1][0]:
                raise CborError("duplicate key")
        return _head(5, len(items)) + b"".join(k + x for k, x in items)
    if isinstance(v, Tag):
        return _head(6, v.tag) + dumps(v.value)
    raise CborError("unsupported type %r" % type(v))


class _Reader(object):
    def __init__(self, data):
        self.d = data
        self.p = 0

    def take(self, n):
        if self.p + n > len(self.d):
            raise CborError("truncated")
        b = self.d[self.p:self.p + n]
        self.p += n
        return b

    def arg(self, info):
        if info < 24:
            return info
        if info == 24:
            v = self.take(1)[0]
            if v < 24:
                raise CborError("non-shortest head")
            return v
        if info == 25:
            v = struct.unpack(">H", self.take(2))[0]
            if v < 256:
                raise CborError("non-shortest head")
            return v
        if info == 26:
            v = struct.unpack(">I", self.take(4))[0]
            if v < 65536:
                raise CborError("non-shortest head")
            return v
        if info == 27:
            v = struct.unpack(">Q", self.take(8))[0]
            if v < (1 << 32):
                raise CborError("non-shortest head")
            return v
        raise CborError("indefinite or reserved additional info")

    def item(self, depth):
        if depth > MAX_DEPTH:
            raise CborError("nesting too deep")
        ib = self.take(1)[0]
        major, info = ib >> 5, ib & 31
        if major == 7:
            if info == 20:
                return False
            if info == 21:
                return True
            if info == 22:
                return None
            raise CborError("unsupported simple value or float")
        n = self.arg(info)
        if major == 0:
            if n > INT_MAX:
                raise CborError("integer out of 64-bit signed range")
            return n
        if major == 1:
            v = -1 - n
            if v < INT_MIN:
                raise CborError("integer out of 64-bit signed range")
            return v
        if major == 2:
            return bytes(self.take(n))
        if major == 3:
            try:
                return bytes(self.take(n)).decode("utf-8")
            except UnicodeDecodeError:
                raise CborError("invalid utf-8")
        if major == 4:
            if n > len(self.d) - self.p:
                raise CborError("truncated")
            return [self.item(depth + 1) for _ in range(n)]
        if major == 5:
            if n > len(self.d) - self.p:
                raise CborError("truncated")
            out = {}
            prev = None
            for _ in range(n):
                ks = self.p
                k = self.item(depth + 1)
                ke = self.p
                kb = bytes(self.d[ks:ke])
                if prev is not None:
                    if kb == prev:
                        raise CborError("duplicate map key")
                    if kb < prev:
                        raise CborError("map keys not sorted")
                prev = kb
                if isinstance(k, (list, dict, Tag)):
                    raise CborError("unsupported map key type")
                out[k] = self.item(depth + 1)
            return out
        if major == 6:
            if n not in ALLOWED_TAGS:
                raise CborError("tag not allowed")
            return Tag(n, self.item(depth + 1))
        raise CborError("bad major type")


def loads(data):
    data = bytes(data)
    r = _Reader(data)
    v = r.item(0)
    if r.p != len(data):
        raise CborError("trailing bytes")
    return v
