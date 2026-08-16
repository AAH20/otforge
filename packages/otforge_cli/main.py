"""otforge command line: run the OT detection-engineering pipeline end to end."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from otforge_detect import synthesize_rules
from otforge_emit import emit_all
from otforge_generate import generate_dataset
from otforge_profiles import PROFILES
from otforge_validate import run_pipeline


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
    args = parser.parse_args(argv)

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
