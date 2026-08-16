# Runbook: aiming the discovery loop at ClamAV (a real memory-safety target)

This is the real campaign. It runs on **your** machine, over **hours to days**, with
**uncertain** results — that is what genuine vulnerability discovery is. Nothing in
this repo claims a ClamAV finding; this is how you go and earn one.

## Why ClamAV, and why native

The `otforge fuzz` demo proves the discover→triage→detect loop. But it fuzzes a
memory-safe Python parser, so it can only surface robustness bugs. **Memory-corruption
CVEs — the kind Talos cares about — live in C code and are found with a compiled
target under a sanitizer.** ClamAV is C, GPLv2, Talos-maintained, and parses
attacker-controlled files. That is the target.

## Beat OSS-Fuzz where it is thin

ClamAV is already fuzzed continuously by Google OSS-Fuzz, so the shallow bugs are gone.
You win by going where OSS-Fuzz coverage is thin:
- **Under-fuzzed / complex unpackers and parsers** (obscure archive and document
  formats) rather than the mainline scan entry.
- **Better inputs**: a real corpus of that format's samples + a format-aware
  dictionary, so the fuzzer reaches deep parser states OSS-Fuzz's generic corpus does not.
- **Structure-aware mutation** seeded from valid files of the specific format.

## Steps

```bash
# 1. Toolchain: clang with libFuzzer + sanitizers.
git clone https://github.com/Cisco-Talos/clamav.git && cd clamav

# 2. Build ClamAV's in-tree fuzz harnesses with ASAN + UBSAN + libFuzzer.
#    Confirm the exact flag names against the current CMake docs before running;
#    ClamAV ships OSS-Fuzz harnesses (scanfile / dbload / format-specific).
cmake -B build -G Ninja \
  -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
  -DENABLE_FUZZ=ON \
  -DCMAKE_C_FLAGS="-fsanitize=address,undefined,fuzzer-no-link -g" \
  -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined,fuzzer-no-link -g"
cmake --build build

# 3. Seed corpus: real samples of the specific format you are targeting.
mkdir corpus && cp /path/to/real/<format>/samples/* corpus/

# 4. Run the harness for the target parser (name depends on ClamAV's fuzz targets).
./build/.../clamav_<target>_fuzzer corpus/ -dict=<format>.dict -max_len=1048576
```

## When it crashes

1. **Minimize** the reproducer (`-minimize_crash=1`) to the smallest triggering file.
2. **Root-cause** from the ASAN/UBSAN report: what kind of bug (heap overflow, OOB
   read, use-after-free, integer overflow leading to a bad allocation).
3. **Prior-art check** — search ClamAV's issue tracker, git log, and the CVE database.
   Most first crashes are already fixed or already reported. Do not claim otherwise.
4. **Coordinated disclosure** — report through ClamAV's / Cisco's security process,
   not a public issue. Let them assign the CVE.

## Where otforge re-enters

Once you have a confirmed crashing input, feed it back through the engine: generate
the FP-validated YARA/detection signature for the malformed structure (the Layer-3
pattern in `otforge_yara`). The **fix goes to Talos; the day-zero detection is yours**
— that is the compounding move, not the free contribution.
