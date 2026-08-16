"""Authorized baselines for three OT protocols, with real operation codes.

Each profile has two legitimate address banks with a real gap between them (the
scanning attack lives in the gap), a small writable range, and a set of genuinely
dangerous out-of-policy codes used by the illegal-function attack.
"""
from __future__ import annotations

from otforge_proto import DeviceProfile

# Modbus/TCP: FC 3/4 read, 6/16 write; illegal/diagnostic codes are anomalous.
MODBUS_PROFILE = DeviceProfile(
    name="plc-line-1",
    protocol="modbus",
    allowed_function_codes=frozenset({3, 4, 6, 16}),
    read_codes=frozenset({3, 4}),
    write_codes=frozenset({5, 6, 15, 16, 23}),
    attack_function_codes=(0, 8, 43, 90, 100),
    valid_register_banks=((0, 1000), (2000, 2100)),
    writable_register_banks=((100, 200),),
    max_read=125,
)

# DNP3: application function codes. READ(1), OPERATE(4) legit; COLD_RESTART(13),
# WARM_RESTART(14), DISABLE_UNSOLICITED(21) are the classic dangerous requests.
DNP3_PROFILE = DeviceProfile(
    name="rtu-substation-a",
    protocol="dnp3",
    allowed_function_codes=frozenset({0, 1, 4}),      # CONFIRM, READ, OPERATE
    read_codes=frozenset({1}),
    write_codes=frozenset({2, 3, 4, 5, 6}),           # WRITE/SELECT/OPERATE/DIRECT_OPERATE(_NR)
    attack_function_codes=(13, 14, 21),
    valid_register_banks=((0, 100), (200, 300)),
    writable_register_banks=((10, 20),),
    max_read=64,
)

# BACnet: confirmed-service choices. ReadProperty(12)/RPM(14) read,
# WriteProperty(15)/WPM(16) write; DeviceCommunicationControl(17) and
# ReinitializeDevice(20) are the dangerous services.
BACNET_PROFILE = DeviceProfile(
    name="bms-ahu-3",
    protocol="bacnet",
    allowed_function_codes=frozenset({12, 14, 15, 16}),
    read_codes=frozenset({12, 14}),
    write_codes=frozenset({7, 15, 16}),               # AtomicWriteFile, WriteProperty, WPM
    attack_function_codes=(17, 20),
    valid_register_banks=((0, 100), (200, 300)),
    writable_register_banks=((10, 20),),
    max_read=50,
)

PROFILES = {"modbus": MODBUS_PROFILE, "dnp3": DNP3_PROFILE, "bacnet": BACNET_PROFILE}
