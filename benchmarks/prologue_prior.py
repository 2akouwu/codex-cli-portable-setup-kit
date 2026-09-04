#!/usr/bin/env python3
"""Benchmark: does the verifier catch a real model hallucination, with zero false accepts?

A language model, asked what a function's entry prologue looks like, tends to
answer the textbook frame-pointer prologue ``push rbp ; mov rbp, rsp``. This
script applies that prior *blind* (it never reads the disassembly itself) to a
corpus of real binaries and measures, purely through reverify's verifier:

- how often the prior is wrong (the model hallucination rate),
- how often a wrong prior is nonetheless marked VERIFIED (must be 0 — the safety
  guarantee), and
- whether the loop reaches the true bytes after one round of tool feedback.

Round 2 re-states the mnemonics the verifier reported in round 1; it demonstrates
the feedback loop converging to ground truth. (Note: in the scored `reconstruct`
loop such a restatement is echo-detected and carries no information weight — the
meaningful result here is round 1.)

Usage:
    python benchmarks/prologue_prior.py [dir ...] [--per-dir N]
Defaults to Windows System32 (x64) and SysWOW64 (x86) if no dirs are given.
"""

import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from reverify.binary import parse_binary
from reverify.verifier import Verifier, Claim, VERIFIED, REFUTED, INCONCLUSIVE

PRIOR = ["push", "mov"]  # the model's textbook frame-pointer prologue guess


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
    return out


def run(dirs, per_dir=12):
    rows = []
    false_verified = 0
    for path in corpus(dirs, per_dir):
        try:
            data = open(path, "rb").read()
        except OSError:
            continue
        info = parse_binary(data)
        if info.format not in ("PE", "ELF", "MachO") or not info.entrypoint:
            continue
        arch = info.arch if info.arch in ("x86", "x86_64", "arm", "arm64") else ("x86_64" if info.bits == 64 else "x86")
        v = Verifier(data)
        r1 = v.verify(Claim("instructions", {"offset": info.entrypoint, "space": "rva", "mnemonics": PRIOR, "arch": arch}))
        if r1["verdict"] == INCONCLUSIVE:
            continue
        actual = r1["evidence"].get("actual_mnemonics", [])
        if r1["verdict"] == VERIFIED and actual[:2] != PRIOR:
            false_verified += 1
        r2 = (v.verify(Claim("instructions", {"offset": info.entrypoint, "space": "rva", "mnemonics": actual[:4], "arch": arch}))
              if actual else {"verdict": INCONCLUSIVE})
        rows.append((os.path.basename(path), arch, r1["verdict"], r2["verdict"], ",".join(actual[:3])))

    tot = len(rows)
    if not tot:
        print("no binaries with a decodable entry point found (need real binaries + capstone/lief)")
        return
    ref = sum(1 for r in rows if r[2] == REFUTED)
    gr = sum(1 for r in rows if r[3] == VERIFIED)
    print(f"{'binary':30}{'arch':7}{'R1 prior':10}{'R2 fixed':10}entry[:3]")
    for b, a, v1, v2, act in rows:
        print(f"{b[:29]:30}{a:7}{v1:10}{v2:10}{act}")
    print("\n==== results ====")
    print(f"binaries tested                 : {tot}")
    print(f"prior wrong (hallucination rate): {ref}/{tot} = {round(100*ref/tot)}%")
    print(f"false VERIFIED (must be 0)       : {false_verified}")
    print(f"true bytes after 1 feedback round: {gr}/{tot} = {round(100*gr/tot)}%")


if __name__ == "__main__":
    argv = sys.argv[1:]
    per = 12
    if "--per-dir" in argv:
        i = argv.index("--per-dir")
        per = int(argv[i + 1])
        del argv[i:i + 2]
    dirs = [a for a in argv if not a.startswith("--")]
    run(dirs, per)
