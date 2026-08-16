"""Property tests for the fuzz -> triage -> detection engine.

Run: PYTHONPATH=packages python3 tests/test_fuzz.py
"""
from __future__ import annotations

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packages"))

from otforge_fuzz import fuzz  # noqa: E402
from otforge_target import build_valid, parse  # noqa: E402
from otforge_yara import validate_detection  # noqa: E402

EXPECTED = {"oob_read", "type_confusion", "null_handler", "resource_exhaustion"}
RESULT = fuzz(6000, random.Random(1337))
BENIGN = [build_valid(bytes([65 + i]) * (i + 1), rc) for i in range(6) for rc in (1, 8, 32, 64)]


def test_valid_files_parse_without_crashing():
    for b in BENIGN:
        assert parse(b) == 3


def test_fuzzer_discovers_every_planted_bug_class():
    assert set(RESULT["unique_classes"]) == EXPECTED
    assert RESULT["crashed"] > 0


def test_each_detection_has_full_recall_and_zero_false_positives():
    for klass, info in RESULT["classes"].items():
        d = validate_detection(klass, info["samples"], BENIGN)
        assert d["recall"] == 1.0, klass          # catches every crash of its class
        assert d["false_positives"] == 0, klass   # never fires on a valid file
        assert d["decision"] == "deploy", klass


def test_detections_emit_yara():
    for klass, info in RESULT["classes"].items():
        d = validate_detection(klass, info["samples"], BENIGN)
        assert d["yara"].startswith("rule OTFORGE_")
        assert klass in d["yara"]


def test_determinism():
    a = fuzz(1000, random.Random(9))
    b = fuzz(1000, random.Random(9))
    assert a["unique_classes"] == b["unique_classes"]
    assert a["crashed"] == b["crashed"]


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} property tests passed")
