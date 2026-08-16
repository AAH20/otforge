"""A small deterministic mutational fuzzer + crash triage.

Mutates a valid seed one byte (or a truncation) at a time, runs the target
parser, and collects the crashes by class. This is Layer 1 (discovery) and the
triage half of Layer 2 of the engine: it turns raw inputs into deduplicated,
classified, reproducible crashes.
"""
from __future__ import annotations

import random
from typing import Dict, List

from otforge_target import Crash, Rejected, build_valid, parse

SEVERITY = {
    "oob_read": "memory-safety",
    "type_confusion": "memory-safety",
    "null_handler": "memory-safety",
    "resource_exhaustion": "denial-of-service",
}


def mutate(data: bytes, rng: random.Random) -> bytes:
    b = bytearray(data)
    if not b:
        return bytes(b)
    strategy = rng.randint(0, 3)
    if strategy == 0:                                   # random byte flip
        b[rng.randrange(len(b))] = rng.randint(0, 255)
    elif strategy == 1:                                 # drive a length/count field high
        b[rng.randrange(len(b))] = rng.randint(200, 255)
    elif strategy == 2:                                 # perturb a type-ish byte
        b[rng.randrange(len(b))] = rng.choice([0, 4, 5, 9, 255])
    elif len(b) > 5:                                    # truncate
        b = b[: rng.randint(4, len(b) - 1)]
    return bytes(b)


def fuzz(iterations: int, rng: random.Random, seed_bytes: bytes = None, keep: int = 40) -> Dict:
    seed = seed_bytes if seed_bytes is not None else build_valid()
    classes: Dict[str, Dict] = {}
    executed = crashed = 0
    for _ in range(iterations):
        inp = mutate(seed, rng)
        executed += 1
        try:
            parse(inp)
        except Crash as c:
            crashed += 1
            entry = classes.setdefault(c.klass, {"count": 0, "samples": []})
            entry["count"] += 1
            if len(entry["samples"]) < keep:
                entry["samples"].append(inp)
        except Rejected:
            pass
    return {
        "executed": executed,
        "crashed": crashed,
        "unique_classes": sorted(classes),
        "classes": {
            k: {"count": v["count"], "severity": SEVERITY.get(k, "unknown"), "samples": v["samples"]}
            for k, v in classes.items()
        },
    }
