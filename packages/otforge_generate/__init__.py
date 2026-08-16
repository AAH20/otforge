"""Profile-driven synthetic OT telemetry: benign stays in policy, attacks violate it.

Works for any DeviceProfile (Modbus, DNP3, BACnet). Benign traffic uses only the
device's legitimate read/write codes and ranges; the four attack classes each
violate one dimension of the profile. Deterministic under a seed.
"""
from __future__ import annotations

import random
from typing import List

from otforge_proto import DeviceProfile, OTRequest, frame_len, invalid_gaps
from otforge_profiles import MODBUS_PROFILE

DEFAULT_PROFILE = MODBUS_PROFILE  # backwards-compatible default

_ENGINEERING_HOSTS = ["10.0.0.10", "10.0.0.11", "10.0.0.12"]
_ADVERSARY = "10.0.0.200"
_PLC = "10.0.0.50"

ATTACK_CLASSES = ("illegal_function", "unauthorized_write", "oob_scan", "illegal_length")


def _req(ts, src, fc, addr, qty, is_write, label, attack=""):
    return OTRequest(
        ts=ts, src=src, dst=_PLC, unit_id=1, function_code=fc, start_address=addr,
        quantity=qty, is_write=is_write, frame_len=frame_len(qty, is_write),
        label=label, attack=attack,
    )


def generate_benign(n: int, profile: DeviceProfile, rng: random.Random) -> List[OTRequest]:
    reads, writes = profile.read_write_codes()
    out: List[OTRequest] = []
    for i in range(n):
        do_write = bool(writes) and (not reads or rng.random() < 0.35)
        if do_write:
            fc = rng.choice(writes)
            wb = rng.choice(profile.writable_register_banks)
            span = wb[1] - wb[0]
            qty = rng.randint(1, min(20, span))
            addr = rng.randint(wb[0], wb[1] - qty)
            out.append(_req(float(i), rng.choice(_ENGINEERING_HOSTS), fc, addr, qty, True, "benign"))
        else:
            fc = rng.choice(reads)
            bank = rng.choice(profile.valid_register_banks)
            span = bank[1] - bank[0]
            qty = rng.randint(1, min(profile.max_read, span))
            addr = rng.randint(bank[0], bank[1] - qty)
            out.append(_req(float(i), rng.choice(_ENGINEERING_HOSTS), fc, addr, qty, False, "benign"))
    return out


def generate_attacks(n: int, profile: DeviceProfile, rng: random.Random) -> List[OTRequest]:
    reads, writes = profile.read_write_codes()
    banks = sorted(profile.valid_register_banks)
    gap = (banks[0][1], banks[1][0]) if len(banks) >= 2 else invalid_gaps(profile)[0]
    out: List[OTRequest] = []
    for i in range(n):
        atk = ATTACK_CLASSES[i % len(ATTACK_CLASSES)]
        if atk == "illegal_function":
            fc = rng.choice(profile.attack_function_codes)
            addr = rng.randint(banks[0][0], banks[0][1] - 1)
            out.append(_req(float(1000 + i), _ADVERSARY, fc, addr, 1, False, "malicious", atk))
        elif atk == "unauthorized_write":
            fc = rng.choice(writes)
            addr = rng.randint(banks[0][0], banks[0][1] - 1)
            while profile.address_writable(addr, 1):
                addr = rng.randint(banks[0][0], banks[0][1] - 1)
            out.append(_req(float(1000 + i), _ADVERSARY, fc, addr, 1, True, "malicious", atk))
        elif atk == "oob_scan":
            fc = rng.choice(reads)
            addr = rng.randint(gap[0], max(gap[0], gap[1] - 2))
            qty = rng.randint(1, max(1, min(20, gap[1] - addr)))
            out.append(_req(float(1000 + i), _ADVERSARY, fc, addr, qty, False, "malicious", atk))
        else:  # illegal_length
            fc = rng.choice(reads)
            addr = rng.randint(banks[0][0], banks[0][1] - 1)
            qty = rng.randint(profile.max_read + 1, profile.max_read + 120)
            out.append(_req(float(1000 + i), _ADVERSARY, fc, addr, qty, False, "malicious", atk))
    return out


def generate_dataset(benign: int, attacks: int, profile: DeviceProfile, seed: int) -> List[OTRequest]:
    rng = random.Random(seed)
    return generate_benign(benign, profile, rng) + generate_attacks(attacks, profile, rng)
