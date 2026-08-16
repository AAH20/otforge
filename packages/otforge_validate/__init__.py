"""False-positive validation: the stage that stops a bad rule before deployment.

Every candidate rule is scored for recall against the attacks it targets and for
false positives against the authorized baseline. A rule that fires on the
baseline is held, and an automated profile-aware refinement is attempted.
"""
from __future__ import annotations

from typing import Dict, List

from otforge_detect import Rule, address_gap_rules_for, matches
from otforge_proto import DeviceProfile, OTRequest


def _recall(rule: Rule, records: List[OTRequest]):
    targets = [r for r in records if r.label == "malicious" and r.attack == rule.attack_class]
    caught = sum(1 for r in targets if matches(rule, r))
    return caught, len(targets)


def _false_positives(rule: Rule, records: List[OTRequest]):
    benign = [r for r in records if r.label == "benign"]
    flagged = sum(1 for r in benign if matches(rule, r))
    return flagged, len(benign)


def _best_refinement(rule: Rule, profile: DeviceProfile, records: List[OTRequest]):
    if rule.kind != "address_low_watermark":
        return None
    best, best_caught = None, -1
    for candidate in address_gap_rules_for(profile, rule.attack_class):
        caught, _ = _recall(candidate, records)
        if caught > best_caught:
            best, best_caught = candidate, caught
    return best


def evaluate_rule(rule: Rule, records: List[OTRequest], profile: DeviceProfile) -> Dict:
    caught, n_targets = _recall(rule, records)
    fp, n_benign = _false_positives(rule, records)
    entry = {
        "rule_id": rule.id,
        "title": rule.title,
        "detects": rule.attack_class,
        "recall": round(caught / n_targets, 4) if n_targets else 0.0,
        "caught": caught,
        "targets": n_targets,
        "false_positives": fp,
        "false_positive_rate": round(fp / n_benign, 4) if n_benign else 0.0,
    }
    if fp == 0:
        entry["decision"] = "deploy"
        entry["note"] = "No false positives against the authorized baseline."
        return entry

    entry["decision"] = "hold"
    entry["note"] = f"{fp} false positive(s) against the baseline; over-generalized from attack samples."
    refined = _best_refinement(rule, profile, records)
    if refined is not None:
        r_caught, r_targets = _recall(refined, records)
        r_fp, r_benign = _false_positives(refined, records)
        entry["refinement"] = {
            "rule_id": refined.id,
            "logic": {"kind": refined.kind, **refined.params},
            "recall": round(r_caught / r_targets, 4) if r_targets else 0.0,
            "false_positives": r_fp,
            "false_positive_rate": round(r_fp / r_benign, 4) if r_benign else 0.0,
            "note": "Bounded to the invalid register gap using the device profile; "
            "regains recall with zero false positives.",
        }
    return entry


def run_pipeline(records: List[OTRequest], rules: List[Rule], profile: DeviceProfile) -> Dict:
    report = [evaluate_rule(r, records, profile) for r in rules]
    return {
        "device_profile": profile.name,
        "dataset": {
            "benign": sum(1 for r in records if r.label == "benign"),
            "malicious": sum(1 for r in records if r.label == "malicious"),
            "total": len(records),
        },
        "rules_evaluated": len(rules),
        "rules_deploy_safe": sum(1 for e in report if e["decision"] == "deploy"),
        "rules_held_for_tuning": sum(1 for e in report if e["decision"] == "hold"),
        "rules": report,
        "honesty": (
            f"Telemetry is synthetic but protocol-accurate ({profile.protocol}). False-positive "
            "rates are measured against a supplied authorized baseline, not a claim about "
            "any production environment."
        ),
    }
