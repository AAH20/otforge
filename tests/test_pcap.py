"""Correctness tests for the Modbus/TCP PCAP generator.

Writes a real pcap, reads it back, and verifies structure AND that the IP and TCP
checksums actually validate (checksum over a header including its own field is 0).

Run: PYTHONPATH=packages python3 tests/test_pcap.py
"""
from __future__ import annotations

import socket
import struct
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packages"))

from otforge_pcap import DNP3_PORT, MODBUS_PORT, _checksum16, dnp3_crc, parse_pcap, write_pcap  # noqa: E402
from otforge_profiles import DNP3_PROFILE, MODBUS_PROFILE  # noqa: E402
from otforge_scenario import build_scenario  # noqa: E402

_DIR = Path(tempfile.mkdtemp())
EVENTS = build_scenario(MODBUS_PROFILE, benign=200, attacks=80, seed=7)
GROUND = write_pcap(EVENTS, str(_DIR / "otforge-modbus.pcap"))
MAGIC, FRAMES = parse_pcap(str(_DIR / "otforge-modbus.pcap"))

DNP3_EVENTS = build_scenario(DNP3_PROFILE, benign=200, attacks=80, seed=7)
write_pcap(DNP3_EVENTS, str(_DIR / "otforge-dnp3.pcap"))
_, DNP3_FRAMES = parse_pcap(str(_DIR / "otforge-dnp3.pcap"))


def test_pcap_header_and_packet_count():
    assert MAGIC == 0xA1B2C3D4
    assert len(FRAMES) == len(EVENTS) == len(GROUND)


def test_every_frame_is_ethernet_ipv4_tcp_modbus():
    for fr in FRAMES:
        assert fr[12:14] == b"\x08\x00"                 # ethertype IPv4
        assert fr[23] == 6                              # IP protocol TCP
        assert struct.unpack("!H", fr[36:38])[0] == MODBUS_PORT   # TCP dst port 502
        # Ethernet(14) + IP(20) + TCP(20) = 54; Modbus MBAP protocol id at 54+2 = 56.
        assert struct.unpack("!H", fr[56:58])[0] == 0   # Modbus protocol id


def test_ip_checksums_validate():
    for fr in FRAMES:
        ip_header = fr[14:34]
        assert _checksum16(ip_header) == 0              # valid IPv4 header checksum


def test_tcp_checksums_validate():
    for fr in FRAMES:
        src, dst = fr[26:30], fr[30:34]
        tcp_and_payload = fr[34:]
        pseudo = src + dst + struct.pack("!BBH", 0, 6, len(tcp_and_payload))
        assert _checksum16(pseudo + tcp_and_payload) == 0   # valid TCP checksum


def test_ground_truth_labels_align():
    attacks = [g for g in GROUND if g["label"] == "malicious"]
    assert attacks and all(g["technique_id"].startswith("T0") for g in attacks)
    assert all(g["technique_id"] == "" for g in GROUND if g["label"] == "benign")


def test_dnp3_crc_matches_the_standard_check_value():
    assert dnp3_crc(b"123456789") == 0xEA82


def test_dnp3_frames_are_well_formed_with_valid_link_crc():
    assert len(DNP3_FRAMES) == len(DNP3_EVENTS)
    for fr in DNP3_FRAMES:
        assert fr[12:14] == b"\x08\x00"                          # IPv4
        assert fr[23] == 6                                       # TCP
        assert struct.unpack("!H", fr[36:38])[0] == DNP3_PORT    # TCP dst port 20000
        assert fr[54:56] == b"\x05\x64"                          # DNP3 start octets
        header8, hcrc = fr[54:62], struct.unpack("<H", fr[62:64])[0]
        assert dnp3_crc(header8) == hcrc                         # link-layer header CRC validates


def test_dnp3_ip_and_tcp_checksums_validate():
    for fr in DNP3_FRAMES:
        assert _checksum16(fr[14:34]) == 0
        tail = fr[34:]
        pseudo = fr[26:30] + fr[30:34] + struct.pack("!BBH", 0, 6, len(tail))
        assert _checksum16(pseudo + tail) == 0


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} property tests passed")
