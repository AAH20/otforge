"""The OT Suricata rules must fire on attacks only — zero false positives.

Run: PYTHONPATH=packages python3 tests/test_rules.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packages"))

from otforge_rules import all_rules, rules_text, validate  # noqa: E402

REPORT = validate(all_rules())


def test_every_rule_has_zero_false_positives():
    for e in REPORT:
        assert e["false_positives"] == 0, e


def test_every_rule_actually_fires_on_attacks():
    for e in REPORT:
        assert e["true_positives"] > 0, e


def test_rules_are_valid_suricata_ot_syntax():
    modbus, dnp3 = rules_text("modbus"), rules_text("dnp3")
    assert modbus.count("alert modbus ") == 4 and "modbus:" in modbus
    assert dnp3.count("alert dnp3 ") == 3 and "dnp3_func:" in dnp3
    for r in all_rules():
        assert f"sid:{r.sid};" in r.suricata and r.suricata.startswith(f"alert {r.protocol} ")


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} property tests passed")
