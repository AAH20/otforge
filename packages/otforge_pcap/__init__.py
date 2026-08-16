"""Real OT capture generation: Modbus/TCP and DNP3/TCP.

Emits genuine, Wireshark-dissectable capture files (Ethernet + IPv4 + TCP + the
OT protocol) with correct IP/TCP checksums, one packet per scenario event, plus a
ground-truth manifest labelling every packet (benign/malicious + ATT&CK-for-ICS).

- **Modbus/TCP** (port 502): MBAP + PDU.
- **DNP3/TCP** (port 20000): full data-link frame (start, length, control, dest,
  src) with the DNP3 CRC-16 (poly 0x3D65, verified against check value 0xEA82),
  a transport octet, and an application-layer request; user data chunked into
  16-octet blocks each with its own CRC, exactly as the DNP3 spec requires.

BACnet/IP (UDP + BVLC/NPDU/APDU) is intentionally not here yet — it needs a UDP
path and a verified APDU encoding, and shipping unverified frames would defeat the
point. Pure standard library.
"""
from __future__ import annotations

import socket
import struct
from typing import Dict, List, Tuple

from otforge_scenario import OTEvent

MODBUS_PORT = 502
DNP3_PORT = 20000


# --------------------------------------------------------------------------- checksums
def _checksum16(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def dnp3_crc(data: bytes) -> int:
    """DNP3 CRC-16 (reflected poly 0x3D65 -> 0xA6BC, xorout 0xFFFF). check=0xEA82."""
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return (~crc) & 0xFFFF


assert dnp3_crc(b"123456789") == 0xEA82, "DNP3 CRC self-test failed"


# --------------------------------------------------------------------------- Modbus
def _modbus_pdu(e: OTEvent) -> bytes:
    fc = e.function_code
    if fc in (3, 4):
        return struct.pack("!BHH", fc, e.point, e.quantity)   # quantity may exceed 125 (attack, on-wire)
    if fc == 6:
        return struct.pack("!BHH", fc, e.point, 0x00FF)
    if fc == 16:
        n = min(e.quantity, 123)
        return struct.pack("!BHHB", fc, e.point, n, 2 * n) + b"\x00" * (2 * n)
    return struct.pack("!BH", fc, e.point)                     # illegal/attack function code


def _modbus_payload(e: OTEvent, index: int) -> bytes:
    pdu = _modbus_pdu(e)
    return struct.pack("!HHHB", index & 0xFFFF, 0, 1 + len(pdu), e.unit_id) + pdu


# --------------------------------------------------------------------------- DNP3
def _dnp3_app(e: OTEvent) -> bytes:
    app_ctrl = 0xC0                                           # FIR, FIN, seq 0
    fc = e.function_code
    obj = b""
    if fc in (1, 2, 4):                                       # read / write / operate carry an object
        group = 41 if e.operation == "write" else 30          # analog output block / analog input
        start = e.point & 0xFF
        stop = (e.point + max(e.quantity, 1) - 1) & 0xFF
        obj = bytes([group, 1, 0x00, start, stop])            # group, var 1, qualifier 0x00, start, stop
    return bytes([app_ctrl, fc]) + obj


def _dnp3_payload(e: OTEvent, index: int) -> bytes:
    user = bytes([0xC0]) + _dnp3_app(e)                       # transport octet (FIR,FIN,seq 0) + app
    length = 5 + len(user)                                    # CONTROL..end-of-user-data
    control, dest, src = 0xC4, 1024, 1                        # master->outstation, unconfirmed user data
    header8 = struct.pack("<BBBBHH", 0x05, 0x64, length, control, dest, src)
    frame = header8 + struct.pack("<H", dnp3_crc(header8))
    for i in range(0, len(user), 16):                         # 16-octet data blocks, each with a CRC
        block = user[i:i + 16]
        frame += block + struct.pack("<H", dnp3_crc(block))
    return frame


# --------------------------------------------------------------------------- L2/L3/L4
def _mac(ip: str) -> bytes:
    return b"\x02\x00" + socket.inet_aton(ip)


def _tcp(sport: int, dport: int, seq: int, ack: int, payload: bytes, src: str, dst: str) -> bytes:
    off_flags = (5 << 12) | 0x018
    hdr0 = struct.pack("!HHIIHHHH", sport, dport, seq, ack, off_flags, 8192, 0, 0)
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(hdr0) + len(payload))
    ck = _checksum16(pseudo + hdr0 + payload)
    return struct.pack("!HHIIHHHH", sport, dport, seq, ack, off_flags, 8192, ck, 0) + payload


def _ipv4(src: str, dst: str, payload: bytes) -> bytes:
    fmt = "!BBHHHBBH4s4s"
    hdr0 = struct.pack(fmt, 0x45, 0, 20 + len(payload), 0x1234, 0x4000, 64, 6, 0,
                       socket.inet_aton(src), socket.inet_aton(dst))
    return struct.pack(fmt, 0x45, 0, 20 + len(payload), 0x1234, 0x4000, 64, 6, _checksum16(hdr0),
                       socket.inet_aton(src), socket.inet_aton(dst)) + payload


def _frame(e: OTEvent, index: int) -> bytes:
    if e.protocol == "dnp3":
        payload, dport = _dnp3_payload(e, index), DNP3_PORT
    elif e.protocol == "modbus":
        payload, dport = _modbus_payload(e, index), MODBUS_PORT
    else:
        raise NotImplementedError(f"pcap encoding for protocol {e.protocol!r} not implemented yet")
    tcp = _tcp(40000 + (index % 20000), dport, 1 + index * 2, 1, payload, e.src_ip, e.dst_ip)
    return _mac(e.dst_ip) + _mac(e.src_ip) + struct.pack("!H", 0x0800) + _ipv4(e.src_ip, e.dst_ip, tcp)


# --------------------------------------------------------------------------- pcap I/O
def write_pcap(events: List[OTEvent], path: str) -> List[Dict]:
    ground: List[Dict] = []
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, e in enumerate(events):
            frame = _frame(e, i)
            ts_sec = int(e.ts)
            ts_usec = int(round((e.ts - ts_sec) * 1_000_000)) % 1_000_000
            f.write(struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame)) + frame)
            ground.append({
                "packet": i, "ts": e.ts, "protocol": e.protocol, "label": e.label,
                "function_code": e.function_code, "point": e.point, "quantity": e.quantity,
                "technique_id": e.technique_id, "technique": e.technique, "uid": e.uid,
            })
    return ground


def parse_pcap(path: str) -> Tuple[int, List[bytes]]:
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
