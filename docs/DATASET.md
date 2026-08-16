# otforge — OT Labelled Capture Dataset (v0.2.1)

Realistic, labelled OT captures are scarce, sensitive, and hard to produce. This
dataset gives detection engineers, Zeek/Suricata/Sigma rule authors, and
researchers a reproducible, per-packet-labelled corpus across **two protocols** to
build and test against.

## What's inside

| File | Contents |
|---|---|
| `modbus/full/otforge-modbus.pcap` | 2,500 Modbus/TCP packets (2,000 benign, 500 malicious) |
| `modbus/sample/otforge-modbus.pcap` | 280 Modbus/TCP packets |
| `dnp3/full/otforge-dnp3.pcap` | 2,500 DNP3/TCP packets (2,000 benign, 500 malicious) |
| `dnp3/sample/otforge-dnp3.pcap` | 280 DNP3/TCP packets |
| `*/otforge-*.groundtruth.json` | per-packet label, function code, register/point, ATT&CK-for-ICS technique, correlation id |
| `*/otforge-*.GROUND_TRUTH.md` | scenario summary and technique counts |

Each `.pcap` is genuine and Wireshark-dissectable:

- **Modbus/TCP** (port 502): Ethernet / IPv4 / TCP / MBAP + PDU, **valid IP and TCP checksums**.
- **DNP3/TCP** (port 20000): Ethernet / IPv4 / TCP / full DNP3 data-link frame with the
  **DNP3 CRC-16** (poly 0x3D65, validated against check value `0xEA82`), transport octet,
  and application request; user data in 16-octet blocks each with its own CRC.

## Attack classes → ATT&CK for ICS

| Class | On-wire | Technique |
|---|---|---|
| `illegal_function` | function/service code the device never serves | T0855 Unauthorized Command Message |
| `unauthorized_write` | write to a non-writable register/point | T0836 Modify Parameter |
| `oob_scan` | reads across the gap between valid banks | T0846 Remote System Discovery |
| `illegal_length` | read count above the protocol/profile maximum | T0814 Denial of Service |

## What it is — and isn't (honest)

- **Synthetic, not captured.** Protocol-accurate Modbus/TCP and DNP3/TCP, generated —
  not a capture from a real PLC/RTU. Attack packets are well-framed but carry the
  malicious content on the wire.
- **For detection development, training, and research** — not a substitute for validation
  against your own real environment.
- Benign traffic stays within an authorised device profile; every malicious packet
  violates exactly one dimension of it and is labelled with its technique. Correlate
  against the log emitters by `uid`.
- **BACnet/IP is not included yet** — it needs a UDP path and a BVLC/NPDU/APDU encoding
  verified against a real capture, and shipping unverified frames would defeat the point.

## Reproduce or extend

```bash
pip install -e .
otforge pcap --protocol modbus --benign 2000 --attacks 500 --seed 7 --out modbus/full
otforge pcap --protocol dnp3   --benign 2000 --attacks 500 --seed 7 --out dnp3/full
```

Fully deterministic under the seed. Source: https://github.com/AAH20/otforge

## License

Dataset: **CC BY 4.0** (attribution). Generating code: Apache-2.0.
