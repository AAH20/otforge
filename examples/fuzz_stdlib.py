"""Aim the otforge harness at a REAL parser: Python's binary-plist reader.

HONEST FRAMING, read this before over-reading any output:
  * Python is memory-safe. This CANNOT find the memory-corruption CVEs Talos
    cares about. At most it surfaces robustness / denial-of-service observations.
  * Any unexpected exception here is near-certainly ALREADY KNOWN in a parser
    this widely used and fuzzed. It is NOT a security finding, and nothing here
    should be reported as a CVE without minimization, prior-art search, and
    coordinated disclosure.
  * Its only job is to show the harness drives real third-party code. Real
    memory-safety discovery needs a native target + sanitizers:
    see harness/clamav/RUNBOOK.md.

Run: PYTHONPATH=packages python3 examples/fuzz_stdlib.py
"""
from __future__ import annotations

import plistlib
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packages"))
from otforge_fuzz import fuzz_callable  # noqa: E402

# Mutated inputs stay seed-sized (~130 B); binary-plist's large-allocation path is
# gated behind a correspondingly large file, so there is no OOM risk here.
SEED = plistlib.dumps(
    {"a": 1, "b": [1, 2, 3, 4], "c": "hello", "d": True, "e": {"x": 1.5}},
    fmt=plistlib.FMT_BINARY,
)
EXPECTED = (plistlib.InvalidFileException, ValueError, EOFError, UnicodeDecodeError)


def is_crash(exc: BaseException):
    if isinstance(exc, EXPECTED):
        return None                                    # handled rejection, not a bug
    if isinstance(exc, MemoryError):
        return "resource_exhaustion (DoS-candidate, likely known)"
    if isinstance(exc, RecursionError):
        return "recursion_depth (DoS-candidate, likely known)"
    return f"unhandled:{type(exc).__name__} (robustness, likely known)"


def target(data: bytes) -> None:
    plistlib.loads(data, fmt=plistlib.FMT_BINARY)


def main() -> None:
    r = fuzz_callable(target, SEED, is_crash, 20000, random.Random(2026))
    print(f"target   : plistlib binary plist reader (CPython {sys.version.split()[0]})")
    print(f"executed : {r['executed']} inputs")
    print(f"outcomes : {r['crashed']} non-expected, {len(r['unique_classes'])} classes")
    if r["classes"]:
        for k, v in r["classes"].items():
            print(f"   {k:52} x{v['count']}")
    else:
        print("   (only handled rejections — the parser rejected every malformed input cleanly)")
    print()
    print("HONEST: robustness/DoS observations at most, near-certainly known, NOT CVEs.")
    print("Real memory-safety discovery -> harness/clamav/RUNBOOK.md")


if __name__ == "__main__":
    main()
