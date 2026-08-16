"""A small deterministic mutational fuzzer + crash triage.

`fuzz_callable` drives ANY parser: you supply the target function, a seed, and an
`is_crash(exc)` classifier that returns a bug-class name or None for an expected
rejection. `fuzz` is the demo-target convenience wrapper. This is Layer 1
(discovery) and the triage half of Layer 2: raw inputs become deduplicated,
classified, reproducible crashes.
"""
from __future__ import annotations

import random
from typing import Callable, Dict, Optional

from otforge_target import Crash, build_valid, parse

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


def fuzz_callable(
    target: Callable[[bytes], object],
    seed: bytes,
    is_crash: Callable[[BaseException], Optional[str]],
    iterations: int,
    rng: random.Random,
    keep: int = 40,
) -> Dict:
    classes: Dict[str, Dict] = {}
    executed = crashed = 0
    for _ in range(iterations):
        inp = mutate(seed, rng)
        executed += 1
        try:
            target(inp)
        except Exception as exc:                        # noqa: BLE001 - a fuzzer catches everything
            klass = is_crash(exc)
            if klass is None:
                continue                                # expected rejection, not a crash
            crashed += 1
            entry = classes.setdefault(klass, {"count": 0, "samples": []})
            entry["count"] += 1
            if len(entry["samples"]) < keep:
                entry["samples"].append(inp)
    return {
        "executed": executed,
        "crashed": crashed,
        "unique_classes": sorted(classes),
        "classes": {
            k: {"count": v["count"], "severity": SEVERITY.get(k, "unknown"), "samples": v["samples"]}
            for k, v in classes.items()
        },
    }


def _demo_is_crash(exc: BaseException) -> Optional[str]:
    return exc.klass if isinstance(exc, Crash) else None


def fuzz(iterations: int, rng: random.Random, seed_bytes: bytes = None, keep: int = 40) -> Dict:
    seed = seed_bytes if seed_bytes is not None else build_valid()
    return fuzz_callable(parse, seed, _demo_is_crash, iterations, rng, keep)
