"""Independent pure-Python reference for PM-CBOR-2026 (RFC 8949 s4.2.1).

TEST TOOLING ONLY. It exists so the shared vectors are checked by a third
implementation, independent of the Rust and Go code. It is not production code
and is not a substitute for the Rust/Go parity gate.
"""
import struct

# Bounds from the architecture-review lock (docs/phase0/11-pmacbor-2026.md).
MAX_WIRE_INPUT = 256 * 1024     # bytes of wire input
MAX_DEPTH = 8                   # container nesting levels
MAX_MAP_ENTRIES = 32
MAX_BSTR = 65552                # 65,536 plaintext + 16-byte Poly1305 tag

CATEGORIES = [
    "ERR_NON_CANONICAL_INTEGER", "ERR_DUPLICATE_MAP_KEY", "ERR_FLOAT_PROHIBITED",
    "ERR_INDEFINITE_LENGTH_PROHIBITED", "ERR_UNSORTED_MAP_KEYS", "ERR_TRAILING_BYTES",
    "ERR_MALFORMED_CBOR", "ERR_UNSUPPORTED_ITEM", "ERR_LIMIT_EXCEEDED",
]


class CborError(Exception):
    def __init__(self, category):
        super().__init__(category)
        self.category = category


class Map(list):
    """List of (key, value) pairs. Pair order is NOT significant when encoding."""


def _head(major, arg):
    m = major << 5
    if arg < 24:
        return bytes([m | arg])
    if arg <= 0xFF:
        return bytes([m | 24, arg])
    if arg <= 0xFFFF:
        return bytes([m | 25]) + struct.pack(">H", arg)
    if arg <= 0xFFFFFFFF:
        return bytes([m | 26]) + struct.pack(">I", arg)
    if arg <= 0xFFFFFFFFFFFFFFFF:
        return bytes([m | 27]) + struct.pack(">Q", arg)
    raise CborError("ERR_UNSUPPORTED_ITEM")


def encode(v, depth=0):
    if v is None:
        return b"\xf6"
    if v is True:
        return b"\xf5"
    if v is False:
        return b"\xf4"
    if isinstance(v, int):
        return _head(0, v) if v >= 0 else _head(1, -1 - v)
    if isinstance(v, (bytes, bytearray)):
        if len(v) > MAX_BSTR:
            raise CborError("ERR_LIMIT_EXCEEDED")
        return _head(2, len(v)) + bytes(v)
    if isinstance(v, str):
        b = v.encode("utf-8")
        return _head(3, len(b)) + b
    if isinstance(v, (Map, list)) and depth >= MAX_DEPTH:
        raise CborError("ERR_LIMIT_EXCEEDED")
    if isinstance(v, Map):
        if len(v) > MAX_MAP_ENTRIES:
            raise CborError("ERR_LIMIT_EXCEEDED")
        pairs = sorted(((encode(k, depth + 1), encode(x, depth + 1)) for k, x in v),
                       key=lambda p: p[0])
        for a, b in zip(pairs, pairs[1:]):
            if a[0] == b[0]:
                raise CborError("ERR_DUPLICATE_MAP_KEY")
        return _head(5, len(pairs)) + b"".join(k + x for k, x in pairs)
    if isinstance(v, list):
        return _head(4, len(v)) + b"".join(encode(x, depth + 1) for x in v)
    raise TypeError(f"unsupported type {type(v)}")


def _take(data, pos, n):
    if n > len(data) - pos[0]:
        raise CborError("ERR_MALFORMED_CBOR")
    s = data[pos[0]:pos[0] + n]
    pos[0] += n
    return s


def _arg(data, pos, ai):
    if ai < 24:
        return ai
    if ai == 24:
        v = _take(data, pos, 1)[0]
        lo = 24
    elif ai == 25:
        v = struct.unpack(">H", _take(data, pos, 2))[0]
        lo = 0x100
    elif ai == 26:
        v = struct.unpack(">I", _take(data, pos, 4))[0]
        lo = 0x10000
    elif ai == 27:
        v = struct.unpack(">Q", _take(data, pos, 8))[0]
        lo = 0x100000000
    else:
        raise CborError("ERR_MALFORMED_CBOR")
    if v < lo:
        raise CborError("ERR_NON_CANONICAL_INTEGER")
    return v


def _item(data, pos, depth):
    ib = _take(data, pos, 1)[0]
    major, ai = ib >> 5, ib & 0x1F
    if 28 <= ai <= 30:
        raise CborError("ERR_MALFORMED_CBOR")
    if ai == 31:
        raise CborError("ERR_INDEFINITE_LENGTH_PROHIBITED" if major in (2, 3, 4, 5)
                        else "ERR_MALFORMED_CBOR")
    if major == 0:
        return _arg(data, pos, ai)
    if major == 1:
        return -1 - _arg(data, pos, ai)
    if major == 2:
        n = _arg(data, pos, ai)
        if n > MAX_BSTR:
            raise CborError("ERR_LIMIT_EXCEEDED")
        return bytes(_take(data, pos, n))
    if major == 3:
        b = _take(data, pos, _arg(data, pos, ai))
        try:
            return bytes(b).decode("utf-8")
        except UnicodeDecodeError:
            raise CborError("ERR_MALFORMED_CBOR")
    if major in (4, 5) and depth >= MAX_DEPTH:
        raise CborError("ERR_LIMIT_EXCEEDED")
    if major == 4:
        n = _arg(data, pos, ai)
        return [_item(data, pos, depth + 1) for _ in range(n)]
    if major == 5:
        n = _arg(data, pos, ai)
        if n > MAX_MAP_ENTRIES:
            raise CborError("ERR_LIMIT_EXCEEDED")
        out, keys = Map(), []
        for _ in range(n):
            start = pos[0]
            k = _item(data, pos, depth + 1)
            keys.append(bytes(data[start:pos[0]]))
            out.append((k, _item(data, pos, depth + 1)))
        if len(set(keys)) != len(keys):
            raise CborError("ERR_DUPLICATE_MAP_KEY")
        if any(a > b for a, b in zip(keys, keys[1:])):
            raise CborError("ERR_UNSORTED_MAP_KEYS")
        return out
    if major == 6:
        raise CborError("ERR_UNSUPPORTED_ITEM")
    # major 7
    if ai == 20:
        return False
    if ai == 21:
        return True
    if ai == 22:
        return None
    if ai in (25, 26, 27):
        raise CborError("ERR_FLOAT_PROHIBITED")
    raise CborError("ERR_UNSUPPORTED_ITEM")


def decode_strict(data):
    if len(data) > MAX_WIRE_INPUT:
        raise CborError("ERR_LIMIT_EXCEEDED")
    pos = [0]
    v = _item(bytes(data), pos, 0)
    if pos[0] != len(data):
        raise CborError("ERR_TRAILING_BYTES")
    return v


# ---- tagged-JSON bridge (vector file value representation) ----
def to_tagged(v):
    if v is None:
        return {"null": True}
    if isinstance(v, bool):
        return {"bool": v}
    if isinstance(v, int):
        return {"int": str(v)}
    if isinstance(v, (bytes, bytearray)):
        return {"bytes": bytes(v).hex()}
    if isinstance(v, str):
        return {"text": v}
    if isinstance(v, Map):
        return {"map": [[to_tagged(k), to_tagged(x)] for k, x in v]}
    if isinstance(v, list):
        return {"array": [to_tagged(x) for x in v]}
    raise TypeError(type(v))


def from_tagged(t):
    assert isinstance(t, dict) and len(t) == 1, t
    (tag, body), = t.items()
    if tag == "null":
        return None
    if tag == "bool":
        return bool(body)
    if tag == "int":
        return int(body)
    if tag == "bytes":
        return bytes.fromhex(body)
    if tag == "text":
        return body
    if tag == "array":
        return [from_tagged(x) for x in body]
    if tag == "map":
        return Map((from_tagged(k), from_tagged(x)) for k, x in body)
    raise ValueError(tag)
