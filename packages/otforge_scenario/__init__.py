"""OT canonical events + multi-format, correlated emitters.

This is the EvidenceForge-shaped layer for OT: one canonical OT event, emitted to
several log formats that share a correlation id (`uid`) and carry ground-truth
labels plus MITRE ATT&CK for ICS technique mappings — the same properties
EvidenceForge gives IT logs, applied to Modbus/DNP3/BACnet. It reuses otforge's
protocol generation as the event source, and is the working prototype behind the
proposed EvidenceForge OT emitter.
"""
from __future__ import annotations

import json
import random
import time
from dataclasses import asdict, dataclass
from typing import Dict, List

from otforge_generate import generate_dataset
from otforge_proto import DeviceProfile

# MITRE ATT&CK for ICS technique per attack class.
TECHNIQUE = {
    "illegal_function": ("T0855", "Unauthorized Command Message"),
    "unauthorized_write": ("T0836", "Modify Parameter"),
    "oob_scan": ("T0846", "Remote System Discovery"),
    "illegal_length": ("T0814", "Denial of Service"),
    "": ("", ""),
}

ACTOR_ROLE = {
    "10.0.0.10": "engineering_workstation",
    "10.0.0.11": "engineering_workstation",
    "10.0.0.12": "hmi",
    "10.0.0.200": "external_host",
}

ASSET_ROLE = {"modbus": "plc", "dnp3": "rtu", "bacnet": "bms_controller"}
PROTO_PORT = {"modbus": 502, "dnp3": 20000, "bacnet": 47808}


@dataclass(frozen=True)
class OTEvent:
    ts: float
    uid: str            # correlation id shared across every emitted format
    protocol: str
    src_ip: str
    src_role: str
    dst_ip: str
    asset_id: str
    asset_role: str
    unit_id: int
    operation: str      # read | write
    function_code: int
    point: int          # register / object index
    quantity: int
    outcome: str        # ok | violation
    label: str          # benign | malicious
    technique_id: str
    technique: str


def _uid(rng: random.Random) -> str:
    return "C" + "".join(rng.choice("0123456789abcdefghijklmnopqrstuv") for _ in range(12))


def build_scenario(profile: DeviceProfile, benign: int = 200, attacks: int = 80,
                   seed: int = 7, start_ts: float = 1_700_000_000.0) -> List[OTEvent]:
    rng = random.Random(seed)
    reqs = generate_dataset(benign, attacks, profile, seed)
    events: List[OTEvent] = []
    t = start_ts
    for r in sorted(reqs, key=lambda x: x.ts):
        t += rng.uniform(0.05, 2.5)                     # inter-arrival jitter (Hawkes stand-in)
        tid, tname = TECHNIQUE.get(r.attack, ("", ""))
        events.append(OTEvent(
            ts=round(t, 3), uid=_uid(rng), protocol=profile.protocol,
            src_ip=r.src, src_role=ACTOR_ROLE.get(r.src, "plc_client"), dst_ip=r.dst,
            asset_id=profile.name, asset_role=ASSET_ROLE.get(profile.protocol, "ot_device"),
            unit_id=r.unit_id, operation="write" if r.is_write else "read",
            function_code=r.function_code, point=r.start_address, quantity=r.quantity,
            outcome="violation" if r.label == "malicious" else "ok",
            label=r.label, technique_id=tid, technique=tname,
        ))
    return events


def to_zeek_ot(e: OTEvent) -> str:
    """A Zeek modbus.log-style TSV record (Zeek ships a native Modbus analyzer)."""
    func = f"{e.operation.upper()}_FC{e.function_code}"
    port = PROTO_PORT.get(e.protocol, 502)
    return "\t".join([f"{e.ts:.6f}", e.uid, e.src_ip, "49152", e.dst_ip, str(port), func, "REQUEST"])


def to_syslog(e: OTEvent) -> str:
    ts = time.strftime("%b %d %H:%M:%S", time.gmtime(e.ts))
    msg = (f"proto={e.protocol} src={e.src_ip}({e.src_role}) asset={e.asset_id} unit={e.unit_id} "
           f"op={e.operation} fc={e.function_code} point={e.point} qty={e.quantity} "
           f"outcome={e.outcome} uid={e.uid}")
    if e.label == "malicious":
        msg += f" attack={e.technique_id}:{e.technique.replace(' ', '_')}"
    return f"{ts} {e.asset_id} otmon: {msg}"


def to_json(e: OTEvent) -> str:
    return json.dumps(asdict(e))


def ground_truth(events: List[OTEvent]) -> str:
    attacks = [e for e in events if e.label == "malicious"]
    by_tech: Dict = {}
    for e in attacks:
        by_tech[(e.technique_id, e.technique)] = by_tech.get((e.technique_id, e.technique), 0) + 1
    lines = [
        "# GROUND_TRUTH (synthetic OT scenario)", "",
        f"Events: {len(events)} total ({len(events) - len(attacks)} benign, {len(attacks)} malicious)",
        f"Assets: {sorted({e.asset_id for e in events})}",
        f"Protocol: {events[0].protocol if events else 'n/a'}", "",
        "## ATT&CK for ICS techniques exercised", "",
    ]
    for (tid, tname), n in sorted(by_tech.items()):
        lines.append(f"- {tid} {tname}: {n} events")
    lines += ["", "Malicious events carry outcome=violation and a technique mapping; benign events",
              "carry outcome=ok and no technique. Correlate across formats by `uid`."]
    return "\n".join(lines)


def emit_all(events: List[OTEvent]) -> Dict[str, List[str]]:
    return {
        "zeek_ot.log": [to_zeek_ot(e) for e in events],
        "ot_syslog.log": [to_syslog(e) for e in events],
        "ot_events.jsonl": [to_json(e) for e in events],
    }
