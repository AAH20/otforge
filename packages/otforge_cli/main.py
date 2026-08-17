"""otforge command line: run the OT detection-engineering pipeline end to end."""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

from otforge_detect import synthesize_rules
from otforge_emit import emit_all
from otforge_fuzz import fuzz
from otforge_generate import generate_dataset
from otforge_pcap import write_pcap
from otforge_profiles import MODBUS_PROFILE, PROFILES
from otforge_rules import all_rules, render_rules_md, rules_text, validate as validate_rules
from otforge_scenario import build_scenario, ground_truth
from otforge_target import build_valid
from otforge_validate import run_pipeline
from otforge_yara import validate_detection


def _print_report(manifest: dict, protocol: str) -> None:
    d = manifest["dataset"]
    print()
    print("  otforge  OT Detection-Engineering Pipeline")
    print("  " + "=" * 64)
    print(f"  Protocol       : {protocol}")
    print(f"  Device profile : {manifest['device_profile']}")
    print(f"  Telemetry      : {d['benign']} benign / {d['malicious']} malicious (synthetic)")
    print(
        f"  Rules          : {manifest['rules_evaluated']} synthesized  ->  "
        f"{manifest['rules_deploy_safe']} deploy-safe, {manifest['rules_held_for_tuning']} held"
    )
    print("  " + "-" * 64)
    print(f"  {'RULE':<18}{'DETECTS':<20}{'RECALL':>7}{'FP-RATE':>9}  DECISION")
    print("  " + "-" * 64)
    for e in manifest["rules"]:
        print(
            f"  {e['rule_id']:<18}{e['detects']:<20}"
            f"{e['recall']*100:>6.0f}%{e['false_positive_rate']*100:>8.1f}%  {e['decision'].upper()}"
        )
        if "refinement" in e:
            r = e["refinement"]
            print(
                f"    -> auto-refined {r['rule_id']}: "
                f"recall {r['recall']*100:.0f}%, FP {r['false_positive_rate']*100:.1f}% (deploy-safe)"
            )
    print("  " + "-" * 64)
    print(f"  {manifest['honesty']}")
    print()


def _fuzz(args) -> int:
    result = fuzz(args.iterations, random.Random(args.seed))
    benign = [build_valid(bytes([65 + i]) * (i + 1), rc) for i in range(6) for rc in (1, 8, 32, 64)]
    detections, yara_blocks = [], []
    for klass, info in result["classes"].items():
        d = validate_detection(klass, info["samples"], benign)
        d["crashes_found"] = info["count"]
        d["severity"] = info["severity"]
        yara_blocks.append(d.pop("yara"))
        detections.append(d)

    print()
    print("  otforge  Fuzz -> Triage -> Detection Engine")
    print("  " + "=" * 66)
    print(f"  Target    : OTF1 demo parser (self-contained, deliberately vulnerable)")
    print(f"  Fuzzing   : {result['executed']} inputs, {result['crashed']} crashes, "
          f"{len(result['unique_classes'])} unique bug classes")
    print("  " + "-" * 66)
    print(f"  {'BUG CLASS':<20}{'SEVERITY':<16}{'FOUND':>6}{'RECALL':>8}{'FP':>6}  DECISION")
    print("  " + "-" * 66)
    for d in detections:
        print(f"  {d['detects']:<20}{d['severity']:<16}{d['crashes_found']:>6}"
              f"{d['recall']*100:>7.0f}%{d['false_positive_rate']*100:>5.0f}%  {d['decision'].upper()}")
    print("  " + "-" * 66)
    print("  Detection synthesized per bug class and false-positive-validated against a")
    print("  benign corpus. Target is a demonstration parser; the same loop points at")
    print("  real parsers next (that is discovery work, not claimed here).")
    print()

    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "crashes.json").write_text(
            json.dumps({"executed": result["executed"], "crashed": result["crashed"],
                        "detections": detections}, indent=2) + "\n", encoding="utf-8")
        (out / "detections.yara").write_text("\n\n".join(yara_blocks) + "\n", encoding="utf-8")
        print(f"  wrote crashes.json, detections.yara to {out}/")
    return 0


def _pcap(args) -> int:
    profile = PROFILES[args.protocol]
    events = build_scenario(profile, benign=args.benign, attacks=args.attacks, seed=args.seed)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    base = f"otforge-{args.protocol}"
    pcap_path = out / f"{base}.pcap"
    ground = write_pcap(events, str(pcap_path))
    (out / f"{base}.groundtruth.json").write_text(json.dumps(ground, indent=2) + "\n", encoding="utf-8")
    (out / f"{base}.GROUND_TRUTH.md").write_text(ground_truth(events) + "\n", encoding="utf-8")

    malicious = sum(1 for g in ground if g["label"] == "malicious")
    port = 502 if args.protocol == "modbus" else 20000
    label = "Modbus" if args.protocol == "modbus" else "DNP3"
    print()
    print(f"  otforge  Labelled {label}/TCP capture dataset")
    print("  " + "=" * 58)
    print(f"  Wrote     : {pcap_path}")
    print(f"  Packets   : {len(ground)}  ({len(ground) - malicious} benign, {malicious} malicious)")
    print(f"  Framing   : Ethernet / IPv4 / TCP:{port} / {label} (valid checksums)")
    print(f"  Labels    : {base}.groundtruth.json + GROUND_TRUTH.md")
    print(f"  Open in Wireshark; every packet is dissectable, every attack is labelled.")
    print()
    return 0


def _rules(args) -> int:
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "otforge-modbus.rules").write_text(rules_text("modbus"), encoding="utf-8")
    (out / "otforge-dnp3.rules").write_text(rules_text("dnp3"), encoding="utf-8")
    report = validate_rules(all_rules())
    (out / "RULES.md").write_text(render_rules_md(report), encoding="utf-8")

    fp = sum(e["false_positives"] for e in report)
    tp = sum(e["true_positives"] for e in report)
    print()
    print("  otforge  OT Suricata rules (false-positive-validated)")
    print("  " + "=" * 60)
    print(f"  Rules     : {len(report)} ({sum(1 for e in report if e['protocol']=='modbus')} modbus, "
          f"{sum(1 for e in report if e['protocol']=='dnp3')} dnp3)")
    print(f"  Validated : {tp} true positives, {fp} false positives, against labelled datasets")
    print(f"  Wrote     : otforge-modbus.rules, otforge-dnp3.rules, RULES.md to {out}/")
    print()
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="otforge", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="generate telemetry, synthesize detection, validate false positives")
    run.add_argument("--protocol", choices=sorted(PROFILES), default="modbus")
    run.add_argument("--benign", type=int, default=400)
    run.add_argument("--attacks", type=int, default=200)
    run.add_argument("--seed", type=int, default=7)
    run.add_argument("--emit", choices=["suricata", "sigma"], help="also write rules in this format")
    run.add_argument("--out", type=str, default="", help="directory for evidence.json, rules.json and emitted rules")
    run.add_argument("--json", action="store_true", help="print the machine-readable manifest only")

    fz = sub.add_parser("fuzz", help="fuzz the demo parser, triage crashes, synthesize + validate detection")
    fz.add_argument("--iterations", type=int, default=6000)
    fz.add_argument("--seed", type=int, default=1337)
    fz.add_argument("--out", type=str, default="", help="directory for crashes.json and detections.yara")

    pc = sub.add_parser("pcap", help="generate a labelled OT capture dataset (.pcap + ground truth)")
    pc.add_argument("--protocol", choices=["modbus", "dnp3"], default="modbus")
    pc.add_argument("--benign", type=int, default=200)
    pc.add_argument("--attacks", type=int, default=80)
    pc.add_argument("--seed", type=int, default=7)
    pc.add_argument("--out", type=str, default="out", help="output directory")

    rl = sub.add_parser("rules", help="emit false-positive-validated OT Suricata rules + RULES.md")
    rl.add_argument("--out", type=str, default="rules", help="output directory")

    args = parser.parse_args(argv)

    if args.command == "fuzz":
        return _fuzz(args)
    if args.command == "pcap":
        return _pcap(args)
    if args.command == "rules":
        return _rules(args)
    if args.command == "run":
        profile = PROFILES[args.protocol]
        records = generate_dataset(args.benign, args.attacks, profile, args.seed)
        rules = synthesize_rules(profile, records)
        manifest = run_pipeline(records, rules, profile)
        manifest["protocol"] = args.protocol

        if args.json:
            print(json.dumps(manifest, indent=2))
        else:
            _print_report(manifest, args.protocol)

        if args.out:
            out = Path(args.out)
            out.mkdir(parents=True, exist_ok=True)
            (out / "evidence.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
            (out / "rules.json").write_text(
                json.dumps([r.to_portable() for r in rules], indent=2) + "\n", encoding="utf-8"
            )
            written = ["evidence.json", "rules.json"]
            if args.emit:
                ext = "rules" if args.emit == "suricata" else "yml"
                name = f"rules.{args.emit}.{ext}"
                (out / name).write_text(emit_all(rules, args.protocol, args.emit), encoding="utf-8")
                written.append(name)
            print(f"  wrote {', '.join(written)} to {out}/")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
