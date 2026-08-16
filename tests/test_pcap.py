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

from otforge_pcap import MODBUS_PORT, _checksum16, parse_pcap, write_pcap  # noqa: E402
from otforge_profiles import MODBUS_PROFILE  # noqa: E402
from otforge_scenario import build_scenario  # noqa: E402

EVENTS = build_scenario(MODBUS_PROFILE, benign=200, attacks=80, seed=7)
_TMP = Path(tempfile.mkdtemp()) / "otforge-modbus.pcap"
GROUND = write_pcap(EVENTS, str(_TMP))
MAGIC, FRAMES = parse_pcap(str(_TMP))


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


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} property tests passed")
