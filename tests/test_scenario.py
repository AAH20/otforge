"""Property tests for the OT scenario + multi-format emitters.

Run: PYTHONPATH=packages python3 tests/test_scenario.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packages"))

from otforge_profiles import BACNET_PROFILE, DNP3_PROFILE, MODBUS_PROFILE  # noqa: E402
from otforge_scenario import (  # noqa: E402
    build_scenario, emit_all, ground_truth, to_json, to_syslog, to_zeek_ot,
)

EVENTS = build_scenario(MODBUS_PROFILE, benign=200, attacks=80, seed=7)


def test_determinism():
    assert build_scenario(DNP3_PROFILE, 50, 20, 3) == build_scenario(DNP3_PROFILE, 50, 20, 3)


def test_labels_map_to_techniques_correctly():
    for e in EVENTS:
        if e.label == "malicious":
            assert e.technique_id.startswith("T0"), e     # every attack has an ICS technique
            assert e.outcome == "violation"
        else:
            assert e.technique_id == ""                   # benign carries none
            assert e.outcome == "ok"


def test_every_format_shares_the_correlation_id():
    for e in EVENTS[:50]:
        assert e.uid in to_zeek_ot(e)
        assert e.uid in to_syslog(e)
        assert e.uid in to_json(e)


def test_json_emitter_is_valid_json():
    for e in EVENTS[:50]:
        assert json.loads(to_json(e))["uid"] == e.uid


def test_zeek_line_uses_the_protocol_port():
    for profile, port in ((MODBUS_PROFILE, "502"), (DNP3_PROFILE, "20000"), (BACNET_PROFILE, "47808")):
        ev = build_scenario(profile, 20, 8, 1)
        assert any(f"\t{port}\t" in to_zeek_ot(e) for e in ev)


def test_emit_all_and_ground_truth():
    formats = emit_all(EVENTS)
    assert set(formats) == {"zeek_ot.log", "ot_syslog.log", "ot_events.jsonl"}
    assert all(len(v) == len(EVENTS) for v in formats.values())
    gt = ground_truth(EVENTS)
    assert "ATT&CK for ICS" in gt and "T0855" in gt


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} property tests passed")
