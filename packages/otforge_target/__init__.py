"""A self-contained, deliberately-vulnerable file-format parser: the fuzz target.

This is an honest demonstration target, not a real product. It parses a tiny TLV
container format (magic ``OTF1`` then ``[type][len:2][value]`` records) over a
bounds-checked buffer that raises on out-of-range access the way a memory
sanitizer aborts a C program. Its bugs are real bug *classes* a fuzzer finds:
out-of-bounds read, type confusion, a null handler, and unbounded expansion.

The same fuzz/triage/detection loop points at real parsers (e.g. ClamAV's) next;
that is discovery work with real toolchains, not something claimed here.
"""
from __future__ import annotations

MAGIC = b"OTF1"
REPEAT_CAP = 64            # max legitimate expansion count
VALID_TYPES = (1, 2, 3)   # DATA, REPEAT, NOP


class Crash(Exception):
    """A memory-safety or resource violation — a sanitizer-style abort."""
    klass = "crash"


class OOBRead(Crash):
    klass = "oob_read"


class TypeConfusion(Crash):
    klass = "type_confusion"


class NullHandler(Crash):
    klass = "null_handler"


class ResourceExhaustion(Crash):
    klass = "resource_exhaustion"


class Rejected(Exception):
    """Input cleanly rejected as invalid — NOT a crash."""


class BoundsCheckedBuffer:
    """Byte access that raises OOBRead past the end, modelling a sanitizer."""

    def __init__(self, data: bytes):
        self._d = data

    def __len__(self) -> int:
        return len(self._d)

    def byte(self, i: int) -> int:
        if i < 0 or i >= len(self._d):
            raise OOBRead(f"read at {i} beyond {len(self._d)}")
        return self._d[i]

    def sliced(self, a: int, b: int) -> bytes:
        if a < 0 or b > len(self._d):
            raise OOBRead(f"slice [{a}:{b}] beyond {len(self._d)}")
        return self._d[a:b]


def _handle_data(buf, vstart, length):
    return None


def _handle_repeat(buf, vstart, length):
    if length < 2:
        raise Rejected("repeat record too short")
    count = buf.byte(vstart)                      # first value byte is the count
    if count > REPEAT_CAP:                        # unbounded expansion guard
        raise ResourceExhaustion(f"repeat count {count} > cap {REPEAT_CAP}")
    return None


def _handle_nop(buf, vstart, length):
    return None


HANDLERS = [None, _handle_data, _handle_repeat, _handle_nop]   # indexed by type; 0 is a hole


def parse(data: bytes) -> int:
    """Parse an OTF1 container. Returns the record count, or raises Crash/Rejected."""
    buf = BoundsCheckedBuffer(data)
    if len(data) < 4 or buf.sliced(0, 4) != MAGIC:
        raise Rejected("bad magic")
    off, records = 4, 0
    while off < len(data):
        rtype = buf.byte(off)
        length = (buf.byte(off + 1) << 8) | buf.byte(off + 2)
        vstart = off + 3
        buf.sliced(vstart, vstart + length)      # OOBRead if the length overruns
        if rtype >= len(HANDLERS):
            raise TypeConfusion(f"type {rtype} out of range")
        handler = HANDLERS[rtype]
        if handler is None:
            raise NullHandler(f"type {rtype} has no handler")
        handler(buf, vstart, length)
        off = vstart + length
        records += 1
    return records


def lenient_scan(data: bytes):
    """Walk records tolerantly (never raises) so detectors can inspect structure."""
    recs = []
    n = len(data)
    if n < 4 or data[:4] != MAGIC:
        return recs
    off = 4
    while off + 3 <= n:
        rtype = data[off]
        length = (data[off + 1] << 8) | data[off + 2]
        vstart = off + 3
        recs.append({"type": rtype, "length": length, "available": n - vstart, "vstart": vstart})
        off = vstart + length
        if off <= vstart:                        # no-progress guard
            break
    return recs


def _record(rtype: int, value: bytes) -> bytes:
    return bytes([rtype, (len(value) >> 8) & 0xFF, len(value) & 0xFF]) + value


def build_valid(data: bytes = b"hello", repeat_count: int = 8) -> bytes:
    body = _record(1, data) + _record(2, bytes([repeat_count, 0x41])) + _record(3, b"")
    return MAGIC + body
