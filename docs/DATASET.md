# otforge — Modbus/TCP Labelled Capture Dataset (v0.2.0)

Realistic, labelled OT captures are scarce, sensitive, and hard to produce. This
dataset gives detection engineers, Zeek/Suricata/Sigma rule authors, and
researchers a reproducible, per-packet-labelled Modbus/TCP corpus to build and
test against.

## What's inside

| File | Contents |
|---|---|
| `full/otforge-modbus.pcap` | 2,500 packets (2,000 benign, 500 malicious) |
| `sample/otforge-modbus.pcap` | 280 packets (200 benign, 80 malicious) |
| `*/otforge-modbus.groundtruth.json` | per-packet label, function code, register, ATT&CK-for-ICS technique, correlation id |
| `*/otforge-modbus.GROUND_TRUTH.md` | scenario summary and technique counts |

Each `.pcap` is genuine **Ethernet / IPv4 / TCP:502 / Modbus** with **valid IP and
TCP checksums** — open directly in Wireshark; every packet dissects.

## Attack classes → ATT&CK for ICS

| Class | On-wire | Technique |
|---|---|---|
| `illegal_function` | function code the device never serves | T0855 Unauthorized Command Message |
| `unauthorized_write` | write to a non-writable register | T0836 Modify Parameter |
| `oob_scan` | reads across the gap between valid banks | T0846 Remote System Discovery |
| `illegal_length` | read count above the Modbus max (125) | T0814 Denial of Service |

## What it is — and isn't (honest)

- **Synthetic, not captured.** These packets are generated to be protocol-accurate
  Modbus/TCP; they are **not** a capture from a real PLC. Attack packets are
  well-framed but carry the malicious content on the wire.
- **For detection development, training, and research** — not a substitute for
  validation against your own real environment.
- Benign traffic stays entirely within an authorised device profile; every
  malicious packet violates exactly one dimension of it and is labelled with its
  technique. Correlate against the log emitters by `uid`.

## Reproduce or extend

```bash
pip install -e .
otforge pcap --benign 2000 --attacks 500 --seed 7 --out full
otforge pcap --benign 200  --attacks 80  --seed 1 --out sample
```

Fully deterministic under the seed. Source: https://github.com/AAH20/otforge

## License

Dataset: **CC BY 4.0** (attribution). Generating code: Apache-2.0.
