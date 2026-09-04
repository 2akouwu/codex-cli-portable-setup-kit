#!/usr/bin/env python3
"""Benchmark: a multi-prior hallucination scorecard for the verifier.

Extends ``prologue_prior.py`` (which probes a single model prior: the textbook
frame-pointer prologue) with more priors that reflect real LLM hallucination
patterns (see issue #4). Each prior is applied *blind* — it never reads the
disassembly itself — and every verdict is measured through reverify's
verifier, with a false-VERIFIED guard:

- if the verifier says VERIFIED, an independent raw check (bypassing the
  verifier) re-confirms the claim actually holds in the bytes; a mismatch is
  counted as a false accept and must be 0.

Priors probed:

- ``prologue``: the textbook x86 frame-pointer prologue ``push rbp ; mov
  rbp, rsp`` at the entry point (regression probe from prologue_prior.py).
- ``md5_const``: the model identifies unknown hashing code as MD5 by quoting
  the MD5 initial constant A0 (0x67452301) — a 32-bit little-endian immediate,
  so the probe is x86-family only (on AArch64 constants are split by
  movz/movk sequences and the byte pattern is not a sound prior).
- ``import_gets``: the model claims the program uses the deprecated C
  function ``gets`` (a classic LLM narrative hallucination).
- ``section_rodata``: the model applies the ELF section name ``.rodata`` to
  PE binaries (which use ``.rdata``) — a cross-format prior.

Usage:
    python benchmarks/hallucination_probes.py [dir ...] [--per-dir N]
                          [--probe name ...]
Defaults to Windows System32/SysWOW64 when present, else /usr/bin + /usr/lib.
"""

import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from reverify.binary import parse_binary
from reverify.verifier import Verifier, Claim, VERIFIED, REFUTED, INCONCLUSIVE

# MD5 initial constant A0 = 0x67452301, as a little-endian 32-bit immediate.
MD5_A0_LE = "01 23 45 67"


def sample(paths, n):
    paths = sorted(paths)
    if len(paths) <= n:
        return paths
    step = len(paths) / n
    return [paths[int(i * step)] for i in range(n)]


def corpus(dirs, per_dir):
    if dirs:
        pairs = []
        for d in dirs:
            files = [p for p in glob.glob(os.path.join(d, "*")) if os.path.isfile(p) and 0 < os.path.getsize(p) < 8 * 1024 * 1024]
            pairs += sample(files, per_dir)
        return pairs
    out = []
    for d in (r"C:\Windows\System32", r"C:\Windows\SysWOW64"):
        if os.path.isdir(d):
            files = [p for p in glob.glob(os.path.join(d, "*.dll")) if 0 < os.path.getsize(p) < 8 * 1024 * 1024]
            out += sample(files, per_dir)
    if out:
        return out
    for d in ("/usr/bin", "/usr/lib"):
        if os.path.isdir(d):
            files = [p for p in glob.glob(os.path.join(d, "*")) if os.path.isfile(p) and 0 < os.path.getsize(p) < 8 * 1024 * 1024]
            out += sample(files, per_dir)
    return out


# --------------------------------------------------------------------------
# Prior probes. Each returns (Claim, guard) or None if not applicable to the
# binary. The guard independently re-checks a VERIFIED verdict against the raw
# bytes / parse (bypassing the verifier) and returns False when the verdict
# would be a false accept.
# --------------------------------------------------------------------------

def probe_prologue(info, data):
    if info.arch not in ("x86", "x86_64") or not info.entrypoint:
        return None
    prior = ["push", "mov"]
    claim = Claim("instructions", {"offset": info.entrypoint, "space": "rva", "mnemonics": prior, "arch": info.arch})

    def guard(verdict, evidence):
        # False => false accept: the verifier marked the prior VERIFIED even
        # though the actual prologue bytes are not the prior.
        if verdict != VERIFIED:
            return True
        return evidence.get("actual_mnemonics", [])[:2] == prior

    return claim, guard


def probe_md5_const(info, data):
    # x86-family only: A0 appears as a contiguous 32-bit LE immediate.
    if info.arch not in ("x86", "x86_64"):
        return None
    # The verifier checks pattern presence over the whole image (there is no
    # windowed claim kind); the guard mirrors that scope. The prior story:
    # the model cites A0 as evidence that a function is MD5 — for binaries
    # that never use MD5 the constant is absent and the prior is a
    # hallucination.
    claim = Claim("pattern_present", {"pattern": MD5_A0_LE})
    needle = bytes.fromhex(MD5_A0_LE.replace(" ", ""))

    def guard(verdict, evidence):
        if verdict != VERIFIED:
            return True
        return needle in data

    return claim, guard


def probe_import_gets(info, data):
    if info.format not in ("PE", "ELF", "MachO"):
        return None
    claim = Claim("import_present", {"function": "gets"})

    def guard(verdict, evidence):
        if verdict != VERIFIED:
            return True
        # Independent check: 'gets' must be in the parsed import table.
        found = False
        for funcs in info.imports.values():
            if "gets" in funcs:
                found = True
                break
        if not found:
            found = any("gets" in (l or "") for l in info.libraries)
        return found

    return claim, guard


def probe_section_rodata(info, data):
    if info.format not in ("PE", "ELF", "MachO"):
        return None
    claim = Claim("section_present", {"name": ".rodata"})

    def guard(verdict, evidence):
        if verdict != VERIFIED:
            return True
        return any(s.name == ".rodata" for s in info.sections)

    return claim, guard


PROBES = [
    ("prologue", probe_prologue, "textbook frame-pointer prologue at entry"),
    ("md5_const", probe_md5_const, "MD5 initial constant A0 near entry"),
    ("import_gets", probe_import_gets, "imports deprecated C gets()"),
    ("section_rodata", probe_section_rodata, "section named .rodata"),
]


def run(dirs, per_dir=12, only=None):
    probes = [p for p in PROBES if only is None or p[0] in only]
    rows = []          # (binary, format, arch, probe, verdict, observed)
    false_verified = 0
    for path in corpus(dirs, per_dir):
        try:
            data = open(path, "rb").read()
        except OSError:
            continue
        info = parse_binary(data)
        if info.format not in ("PE", "ELF", "MachO"):
            continue
        v = Verifier(data)
        for name, factory, _desc in probes:
            built = factory(info, data)
            if built is None:
                continue
            claim, guard = built
            r = v.verify(claim)
            verdict = r["verdict"]
            if verdict == VERIFIED and not guard(verdict, r["evidence"]):
                false_verified += 1
            observed = r["evidence"].get("actual") or r["evidence"].get("match_count") or ""
            rows.append((os.path.basename(path), info.format, info.arch, name, verdict, str(observed)[:40]))

    if not rows:
        print("no parseable binaries found (need real binaries)")
        return
    probes_ran = [p[0] for p in probes]
    print(f"{'binary':30}{'fmt':6}{'arch':7}{'probe':14}{'verdict':11}observed")
    for b, fmt, arch, pn, vd, obs in rows:
        print(f"{b[:29]:30}{fmt:6}{arch:7}{pn:14}{vd:11}{obs}")
    print("\n==== hallucination scorecard ====")
    print(f"{'probe':14}{'dec.':>6}  {'prior wrong':<12}{'prior right':>11}{'inconcl.':>9}")
    for pn in probes_ran:
        sub = [r for r in rows if r[3] == pn]
        decidable = [r for r in sub if r[4] in (VERIFIED, REFUTED)]
        ref = sum(1 for r in decidable if r[4] == REFUTED)
        ver = sum(1 for r in decidable if r[4] == VERIFIED)
        inc = sum(1 for r in sub if r[4] == INCONCLUSIVE)
        base = len(decidable) or 1
        wrong = f"{ref}/{base} = {round(100 * ref / base)}%"
        print(f"{pn:14}{len(decidable):>6}  {wrong:<12}{ver:>11}{inc:>9}")
    print(f"\nglobal false VERIFIED (must be 0): {false_verified}")


if __name__ == "__main__":
    argv = sys.argv[1:]
    per = 12
    only = None
    if "--per-dir" in argv:
        i = argv.index("--per-dir")
        per = int(argv[i + 1])
        del argv[i:i + 2]
    if "--probe" in argv:
        i = argv.index("--probe")
        vals = []
        while i < len(argv) and not argv[i].startswith("--"):
            vals.append(argv[i])
            i += 1
        del argv[argv.index("--probe"):i]
        only = vals or None
    dirs = [a for a in argv if not a.startswith("--")]
    run(dirs, per, only)
