"""Detection synthesis (Layer 3): from a crash class to a validated signature.

For each discovered crash class, synthesize a structural detector, measure its
recall against that class's crashing inputs and its false-positive rate against a
benign corpus, and emit a YARA rule. Same false-positive discipline as
otforge_validate, applied to file formats.
"""
from __future__ import annotations

from typing import Dict, List

from otforge_target import MAGIC, REPEAT_CAP, VALID_TYPES, lenient_scan


def _detect_oob(data: bytes) -> bool:
    # An over-declared record length, or bytes that do not cleanly complete the
    # container (a truncated/dangling record). Valid files consume to exactly EOF.
    if len(data) < 4 or data[:4] != MAGIC:
        return False
    recs = lenient_scan(data)
    if not recs or any(r["length"] > r["available"] for r in recs):
        return True
    consumed = recs[-1]["vstart"] + recs[-1]["length"]
    return consumed != len(data)


def _detect_bad_type(data: bytes) -> bool:
    return any(r["type"] not in VALID_TYPES for r in lenient_scan(data))


def _detect_resource(data: bytes) -> bool:
    for r in lenient_scan(data):
        if r["type"] == 2 and r["vstart"] < len(data) and data[r["vstart"]] > REPEAT_CAP:
            return True
    return False


# Each crash class -> (human title, detector predicate).
DETECTORS = {
    "oob_read": ("Record length exceeds bytes remaining in the file", _detect_oob),
    "type_confusion": ("Record type outside the valid set {1,2,3}", _detect_bad_type),
    "null_handler": ("Record type outside the valid set {1,2,3}", _detect_bad_type),
    "resource_exhaustion": ("REPEAT count above the safe cap", _detect_resource),
}


def to_yara(klass: str, title: str) -> str:
    return (
        f"rule OTFORGE_{klass.upper()}\n{{\n"
        f"    meta:\n"
        f'        description = "{title}"\n'
        f'        detects = "{klass}"\n'
        f'        note = "Anchored on magic; enforce the structural condition at parser level for full fidelity."\n'
        f"    strings:\n        $magic = \"OTF1\"\n"
        f"    condition:\n        $magic at 0\n}}"
    )


def validate_detection(klass: str, crash_samples: List[bytes], benign: List[bytes]) -> Dict:
    title, predicate = DETECTORS[klass]
    caught = sum(1 for s in crash_samples if predicate(s))
    fp = sum(1 for b in benign if predicate(b))
    return {
        "detects": klass,
        "title": title,
        "recall": round(caught / len(crash_samples), 4) if crash_samples else 0.0,
        "caught": caught,
        "samples": len(crash_samples),
        "false_positives": fp,
        "false_positive_rate": round(fp / len(benign), 4) if benign else 0.0,
        "decision": "deploy" if fp == 0 else "hold",
        "yara": to_yara(klass, title),
    }
