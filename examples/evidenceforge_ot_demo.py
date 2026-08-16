"""Prototype: correlated, multi-format, ground-truth-labeled OT logs.

Demonstrates the EvidenceForge model applied to OT (Modbus/DNP3/BACnet): one
canonical OT event emitted to Zeek-style, syslog, and JSON, all sharing a `uid`,
with an ATT&CK-for-ICS ground truth. This is the working prototype referenced by
the EvidenceForge OT-emitter proposal.

Run: PYTHONPATH=packages python3 examples/evidenceforge_ot_demo.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packages"))
from otforge_profiles import MODBUS_PROFILE  # noqa: E402
from otforge_scenario import build_scenario, emit_all, ground_truth, to_syslog, to_zeek_ot  # noqa: E402


def main() -> None:
    events = build_scenario(MODBUS_PROFILE, benign=200, attacks=80, seed=7)
    formats = emit_all(events)

    print(f"generated {len(events)} correlated OT events -> "
          f"{', '.join(formats)} (all share `uid`)\n")

    sample = next(e for e in events if e.label == "malicious")
    print("Same malicious event, three formats, one correlation id:")
    print("  zeek   :", to_zeek_ot(sample))
    print("  syslog :", to_syslog(sample))
    print(f"  (uid {sample.uid} appears in all three)\n")

    print(ground_truth(events))


if __name__ == "__main__":
    main()
