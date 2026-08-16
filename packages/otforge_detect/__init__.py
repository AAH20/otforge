"""Detection synthesis: candidate rules from a device profile and observed attacks.

Rules are pure data (a kind plus parameters) with a separate evaluator, so each
rule serializes faithfully to a portable, vendor-neutral representation and to
Suricata/Sigma (see otforge_emit).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from otforge_proto import DeviceProfile, OTRequest, invalid_gaps


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    attack_class: str
    kind: str
    params: Dict
    rationale: str

    def to_portable(self) -> Dict:
        return {
            "id": self.id,
            "title": self.title,
            "detects": self.attack_class,
            "logic": {"kind": self.kind, **self.params},
            "rationale": self.rationale,
        }


def matches(rule: Rule, rec: OTRequest) -> bool:
    k, p = rule.kind, rule.params
    if k == "fc_allowlist":
        return rec.function_code not in set(p["allowed"])
    if k == "write_protect":
        if rec.function_code not in set(p["write_fcs"]):
            return False
        end = rec.start_address + max(rec.quantity, 1)
        return not any(s <= rec.start_address and end <= e for s, e in p["writable"])
    if k == "quantity_max":
        return rec.function_code in set(p["read_fcs"]) and rec.quantity > p["max_quantity"]
    if k == "address_low_watermark":
        return rec.start_address >= p["threshold"]
    if k == "address_gap":
        return p["gap_start"] <= rec.start_address < p["gap_end"]
    return False


def address_gap_rules_for(profile: DeviceProfile, attack_class: str) -> List[Rule]:
    rules = []
    for i, (gs, ge) in enumerate(invalid_gaps(profile)):
        rules.append(
            Rule(
                id=f"otf-addr-gap-{i}",
                title=f"Access to invalid address gap [{gs},{ge})",
                attack_class=attack_class,
                kind="address_gap",
                params={"gap_start": gs, "gap_end": ge},
                rationale="Addresses between authorized banks are never touched by legitimate clients.",
            )
        )
    return rules


def synthesize_rules(profile: DeviceProfile, records: List[OTRequest]) -> List[Rule]:
    malicious = [r for r in records if r.label == "malicious"]
    rules: List[Rule] = [
        Rule(
            id="otf-fc-allow",
            title="Function code outside the device allowlist",
            attack_class="illegal_function",
            kind="fc_allowlist",
            params={"allowed": sorted(profile.allowed_function_codes)},
            rationale="This device serves a fixed set of function codes; anything else is anomalous.",
        ),
        Rule(
            id="otf-write-protect",
            title="Write to a non-writable address range",
            attack_class="unauthorized_write",
            kind="write_protect",
            params={
                "write_fcs": sorted(profile.write_codes),
                "writable": [list(b) for b in profile.writable_register_banks],
            },
            rationale="Only the setpoint range is writable; writes elsewhere are unauthorized.",
        ),
        Rule(
            id="otf-qty-max",
            title="Read count exceeds the device/protocol maximum",
            attack_class="illegal_length",
            kind="quantity_max",
            params={"read_fcs": sorted(profile.read_codes), "max_quantity": profile.max_read},
            rationale="Reads above the profile ceiling are malformed or abusive.",
        ),
    ]
    oob = [r for r in malicious if r.attack == "oob_scan"]
    if oob:
        threshold = min(r.start_address for r in oob)
        rules.append(
            Rule(
                id="otf-addr-naive",
                title=f"Address at or above {threshold} (naive, data-derived)",
                attack_class="oob_scan",
                kind="address_low_watermark",
                params={"threshold": threshold},
                rationale="Derived from the minimum address seen in scanning traffic; "
                "intentionally naive to exercise false-positive validation.",
            )
        )
    return rules
