"""Real Modbus/TCP PCAP generation from OT scenario events.

Emits genuine, Wireshark-dissectable capture files: Ethernet + IPv4 + TCP +
Modbus, with correct IP and TCP checksums, one packet per scenario event, plus a
ground-truth manifest labelling every packet (benign / malicious + ATT&CK-for-ICS
technique). Labelled OT captures are scarce; this produces them, reproducibly and
for free. Pure standard library.

Scope: Modbus/TCP, encoded correctly (DNP3/BACnet PDU encoding is next). Attack
packets are well-framed but carry the malicious content on the wire (illegal
function code, write to a protected register, out-of-range read, over-spec count).
"""
from __future__ import annotations

import socket
import struct
from typing import Dict, List, Tuple

from otforge_scenario import OTEvent

MODBUS_PORT = 502


def _checksum16(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def _mac(ip: str) -> bytes:
    return b"\x02\x00" + socket.inet_aton(ip)          # locally-administered MAC from IP


def _modbus_pdu(e: OTEvent) -> bytes:
    fc = e.function_code
    if fc in (3, 4):                                    # read holding/input registers
        return struct.pack("!BHH", fc, e.point, e.quantity)   # quantity may be > 125 (attack, on-wire)
    if fc == 6:                                          # write single register
        return struct.pack("!BHH", fc, e.point, 0x00FF)
    if fc == 16:                                         # write multiple registers
        n = min(e.quantity, 123)
        return struct.pack("!BHHB", fc, e.point, n, 2 * n) + b"\x00" * (2 * n)
    return struct.pack("!BH", fc, e.point)              # illegal/attack function code


def _modbus_adu(unit_id: int, pdu: bytes, txid: int) -> bytes:
    return struct.pack("!HHHB", txid & 0xFFFF, 0, 1 + len(pdu), unit_id) + pdu


def _tcp(sport: int, dport: int, seq: int, ack: int, payload: bytes, src: str, dst: str) -> bytes:
    offset_flags = (5 << 12) | 0x018                    # data offset 5 words, PSH+ACK
    hdr0 = struct.pack("!HHIIHHHH", sport, dport, seq, ack, offset_flags, 8192, 0, 0)
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(hdr0) + len(payload))
    ck = _checksum16(pseudo + hdr0 + payload)
    return struct.pack("!HHIIHHHH", sport, dport, seq, ack, offset_flags, 8192, ck, 0) + payload


def _ipv4(src: str, dst: str, payload: bytes) -> bytes:
    total = 20 + len(payload)
    fmt = "!BBHHHBBH4s4s"
    hdr0 = struct.pack(fmt, 0x45, 0, total, 0x1234, 0x4000, 64, 6, 0,
                       socket.inet_aton(src), socket.inet_aton(dst))
    ck = _checksum16(hdr0)
    return struct.pack(fmt, 0x45, 0, total, 0x1234, 0x4000, 64, 6, ck,
                       socket.inet_aton(src), socket.inet_aton(dst)) + payload


def _frame(e: OTEvent, index: int, dst_port: int) -> bytes:
    adu = _modbus_adu(e.unit_id, _modbus_pdu(e), txid=index)
    sport = 40000 + (index % 20000)
    tcp = _tcp(sport, dst_port, 1 + index * 2, 1, adu, e.src_ip, e.dst_ip)
    ip = _ipv4(e.src_ip, e.dst_ip, tcp)
    return _mac(e.dst_ip) + _mac(e.src_ip) + struct.pack("!H", 0x0800) + ip


def write_pcap(events: List[OTEvent], path: str, dst_port: int = MODBUS_PORT) -> List[Dict]:
    ground: List[Dict] = []
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))   # pcap global header
        for i, e in enumerate(events):
            frame = _frame(e, i, dst_port)
            ts_sec = int(e.ts)
            ts_usec = int(round((e.ts - ts_sec) * 1_000_000)) % 1_000_000
            f.write(struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame)))
            f.write(frame)
            ground.append({
                "packet": i, "ts": e.ts, "label": e.label, "function_code": e.function_code,
                "point": e.point, "quantity": e.quantity, "technique_id": e.technique_id,
                "technique": e.technique, "uid": e.uid,
            })
    return ground


def parse_pcap(path: str) -> Tuple[int, List[bytes]]:
    """Read a pcap back to its magic + raw frames (for validation)."""
    frames: List[bytes] = []
    with open(path, "rb") as f:
        magic = struct.unpack("<I", f.read(24)[:4])[0]
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                break
            _, _, incl, _ = struct.unpack("<IIII", rec)
            frames.append(f.read(incl))
    return magic, frames
