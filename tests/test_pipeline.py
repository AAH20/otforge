"""Property tests: invariants the pipeline must hold across every protocol.

Run: PYTHONPATH=packages python3 tests/test_pipeline.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packages"))

from otforge_detect import synthesize_rules  # noqa: E402
from otforge_emit import to_sigma, to_suricata  # noqa: E402
from otforge_generate import generate_dataset  # noqa: E402
from otforge_profiles import PROFILES  # noqa: E402
from otforge_validate import evaluate_rule, run_pipeline  # noqa: E402


def _fixture(protocol):
    profile = PROFILES[protocol]
    records = generate_dataset(400, 200, profile, seed=7)
    rules = synthesize_rules(profile, records)
    return profile, records, {r.id: r for r in rules}, rules


def test_benign_traffic_honors_the_profile():
    for protocol in PROFILES:
        profile, records, _, _ = _fixture(protocol)
        for r in (x for x in records if x.label == "benign"):
            assert r.function_code in profile.allowed_function_codes, protocol
            if r.is_write:
                assert profile.address_writable(r.start_address, r.quantity), protocol
            else:
                assert profile.address_valid(r.start_address, r.quantity), protocol
                assert r.quantity <= profile.max_read, protocol


def test_every_attack_actually_violates_policy():
    for protocol in PROFILES:
        profile, records, _, _ = _fixture(protocol)
        for r in (x for x in records if x.label == "malicious"):
            if r.attack == "illegal_function":
                assert r.function_code not in profile.allowed_function_codes, protocol
            elif r.attack == "unauthorized_write":
                assert not profile.address_writable(r.start_address, r.quantity), protocol
            elif r.attack == "oob_scan":
                assert not profile.address_valid(r.start_address, r.quantity), protocol
            elif r.attack == "illegal_length":
                assert r.quantity > profile.max_read, protocol


def test_profile_rules_are_perfect_and_clean():
    for protocol in PROFILES:
        profile, records, by_id, _ = _fixture(protocol)
        for rid in ("otf-fc-allow", "otf-write-protect", "otf-qty-max"):
            e = evaluate_rule(by_id[rid], records, profile)
            assert e["recall"] == 1.0, (protocol, rid)
            assert e["false_positives"] == 0, (protocol, rid)
            assert e["decision"] == "deploy", (protocol, rid)


def test_naive_address_rule_false_positives_then_auto_refines():
    for protocol in PROFILES:
        profile, records, by_id, _ = _fixture(protocol)
        e = evaluate_rule(by_id["otf-addr-naive"], records, profile)
        assert e["recall"] == 1.0, protocol            # catches every scan
        assert e["false_positives"] > 0, protocol      # but fires on the second valid bank
        assert e["decision"] == "hold", protocol
        ref = e["refinement"]
        assert ref["recall"] == 1.0, protocol          # refinement keeps recall
        assert ref["false_positives"] == 0, protocol   # and eliminates false positives


def test_emitters_carry_the_rule_identity():
    profile, records, _, rules = _fixture("modbus")
    for rule in rules:
        s = to_suricata(rule, "modbus")
        y = to_sigma(rule, "modbus")
        assert rule.attack_class in s and "sid:" in s
        assert rule.id in y and "detection:" in y


def test_determinism():
    p = PROFILES["dnp3"]
    assert generate_dataset(50, 50, p, seed=3) == generate_dataset(50, 50, p, seed=3)


def test_manifest_summary_counts_are_consistent():
    profile, records, _, rules = _fixture("bacnet")
    m = run_pipeline(records, rules, profile)
    assert m["dataset"]["total"] == 600
    assert m["rules_deploy_safe"] + m["rules_held_for_tuning"] == m["rules_evaluated"]


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} property tests passed")
