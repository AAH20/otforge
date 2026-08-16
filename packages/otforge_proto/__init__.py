"""Protocol-neutral OT request model and an authorized device baseline.

The pipeline reasons at the semantic request layer these OT protocols share:
an operation/function/service code, an address/point/object index, a count, and
whether it writes. Modbus, DNP3 and BACnet all map onto it. Nothing here talks
to a real device.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

# Modbus reference constants (used by the Modbus profile).
READ_HOLDING_REGISTERS = 3
READ_INPUT_REGISTERS = 4
WRITE_SINGLE_REGISTER = 6
WRITE_MULTIPLE_REGISTERS = 16
MAX_READ_REGISTERS = 125
MBAP_HEADER_LEN = 7


@dataclass(frozen=True)
class DeviceProfile:
    """The authorized behavioural baseline an OT asset owner can supply.

    ``valid_register_banks`` / ``writable_register_banks`` are half-open
    [start, end) ranges over the protocol's address space (registers, points,
    or object instances depending on the protocol).
    """

    name: str
    protocol: str
    allowed_function_codes: frozenset
    read_codes: frozenset
    write_codes: frozenset
    attack_function_codes: Tuple[int, ...]   # real out-of-policy / dangerous codes
    valid_register_banks: Tuple[Tuple[int, int], ...]
    writable_register_banks: Tuple[Tuple[int, int], ...]
    max_read: int

    def address_valid(self, addr: int, quantity: int) -> bool:
        end = addr + max(quantity, 1)
        return any(s <= addr and end <= e for s, e in self.valid_register_banks)

    def address_writable(self, addr: int, quantity: int) -> bool:
        end = addr + max(quantity, 1)
        return any(s <= addr and end <= e for s, e in self.writable_register_banks)

    def read_write_codes(self):
        """The legitimate read and write codes = allowlist intersected with each role."""
        return (
            sorted(self.allowed_function_codes & self.read_codes),
            sorted(self.allowed_function_codes & self.write_codes),
        )


@dataclass(frozen=True)
class OTRequest:
    """One OT request at the semantic layer, across Modbus / DNP3 / BACnet."""

    ts: float
    src: str
    dst: str
    unit_id: int
    function_code: int
    start_address: int
    quantity: int
    is_write: bool
    frame_len: int
    label: str          # "benign" | "malicious"
    attack: str = ""    # attack class when malicious


def frame_len(quantity: int, is_write: bool) -> int:
    """Approximate on-wire request length: header plus payload for writes."""
    return 10 + (2 * max(quantity, 1) if is_write else 0)


def invalid_gaps(profile: DeviceProfile, upper: int = 65536) -> List[Tuple[int, int]]:
    """The address ranges *between and beyond* the valid banks — never touched legitimately."""
    banks = sorted(profile.valid_register_banks)
    gaps: List[Tuple[int, int]] = []
    prev = 0
    for start, end in banks:
        if start > prev:
            gaps.append((prev, start))
        prev = max(prev, end)
    if prev < upper:
        gaps.append((prev, upper))
    return gaps
