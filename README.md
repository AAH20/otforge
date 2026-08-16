# otforge — OT Detection-Engineering Pipeline

**Generate protocol-accurate ICS telemetry, synthesize detection, and prove the false-positive rate before anything ships.**

A detection rule that fires on legitimate traffic is worse than no rule at all — at scale it buries real signal and burns the one thing a threat-intel team can't buy back: analyst time. `otforge` is the assembly line that stops that from happening: it takes a device's authorized baseline, generates faithful OT telemetry (benign **and** four documented attack classes) for **Modbus, DNP3, or BACnet**, synthesizes candidate detection, **measures each rule's recall and false-positive rate against the baseline** — holding any rule that would misfire and attempting an automated, profile-aware refinement — and emits the survivors as vendor-neutral **Suricata** or **Sigma**.

```
$ otforge run

  otforge  OT Detection-Engineering Pipeline
  ================================================================
  Device profile : plc-line-1
  Telemetry      : 400 benign / 200 malicious (synthetic, Modbus/TCP)
  Rules          : 4 synthesized  ->  3 deploy-safe, 1 held
  ----------------------------------------------------------------
  RULE              DETECTS              RECALL  FP-RATE  DECISION
  ----------------------------------------------------------------
  otf-fc-allow      illegal_function       100%     0.0%  DEPLOY
  otf-write-protect unauthorized_write     100%     0.0%  DEPLOY
  otf-qty-max       illegal_length         100%     0.0%  DEPLOY
  otf-addr-naive    oob_scan               100%    21.2%  HOLD
    -> auto-refined otf-addr-gap-0: recall 100%, FP 0.0% (deploy-safe)
```

That last line is the whole point. A naive rule derived from attack samples catches every scan **and** false-positives on a second legitimate register bank. The pipeline catches it against the baseline and bounds it to the real invalid gap — full recall, zero false positives — **before** it would ever reach a sensor.

## The problem it addresses

Threat-intel teams generate detection at scale (thousands of rules a year) against enormous install bases, where a single false-positive-prone rule is an operational incident. The bottleneck is not writing rules — it is **validating** them cheaply, especially for **OT/ICS**, where labeled malicious data barely exists. `otforge` treats detection like software: synthesize, test against a known-good baseline, gate on regression, keep humans on the uncertain cases only.

## The four attack classes (Modbus/TCP)

| Class | What it is | Rule that catches it |
|---|---|---|
| `illegal_function` | function code the device never serves | function-code allowlist |
| `unauthorized_write` | write to a non-writable register bank | write-protection |
| `illegal_length` | read quantity above the Modbus spec max (125) | quantity ceiling |
| `oob_scan` | reads across the gap between valid register banks | invalid-gap (after FP refinement) |

## Install & run

```bash
git clone <this repo> && cd otforge
pip install -e .                                    # gives you the `otforge` command
otforge run --protocol modbus --out out             # modbus | dnp3 | bacnet
otforge run --protocol dnp3 --emit sigma --out out  # also write vendor-neutral Sigma
# or with no install:
PYTHONPATH=packages python3 -m otforge_cli.main run
```

Pure standard library, deterministic under a seed, no runtime dependencies.

## Architecture

```
packages/
  otforge_proto      protocol-neutral OT request model + DeviceProfile baseline
  otforge_profiles   authorized baselines for Modbus, DNP3 and BACnet (real op codes)
  otforge_generate   protocol-accurate benign + attack telemetry (seeded)
  otforge_detect     detection synthesis; rules are portable data + an evaluator
  otforge_validate   recall + false-positive scoring, hold/deploy, auto-refinement
  otforge_emit       vendor-neutral Suricata and Sigma emitters
  otforge_cli        the `otforge` command
```

This is the substance behind the [Aegis_CM_Swarm](https://github.com/AAH20/Aegis_CM_Swarm) observe→analyze→act pattern: the generator is the adversary/observer, the validator is the commander that decides what is safe to deploy. Every run is reproducible; invariants are enforced by `python3 tests/test_pipeline.py`.

## What it is, and isn't — honestly

- **The telemetry is synthetic but protocol-accurate.** Real function codes, real spec maxima, real framing. It is *not* a capture from a production PLC, and false-positive rates are measured against a *supplied* baseline — never presented as a claim about any real environment.
- **It is a methodology engine, not a scale claim.** At a real install base, the same pipeline runs against real benign telemetry; here it proves the method on a reproducible proxy.
- **Detection is vendor-neutral.** Rules are portable data (`rules.json`), not tied to any one SIEM.

## Roadmap to real-world proof

1. Replace synthetic benign traffic with **real captured** Modbus/DNP3/BACnet baselines.
2. Feed the malicious side from a **firmware-rehosting fuzzer** (real crashes → real signatures).
3. Add DNP3, BACnet, and OPC-UA profiles.
4. Emit Suricata and Sigma directly, with the false-positive evidence attached.

## License

Apache-2.0.
