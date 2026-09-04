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

Evidence, not anecdote: ``--json`` writes a machine-readable record with the
SHA-256 of every binary tested, the tool versions, the platform and the exact
verdicts, so a third party can replicate the run file by file; ``--markdown``
renders the same record as a table; ``--fail-on-false-verified`` turns the
soundness guarantee into a CI gate. The corpus is sampled deterministically
(sorted, fixed stride), so two runs on the same machine test the same files.

Usage:
    python benchmarks/prologue_prior.py [dir ...] [--per-dir N] [--json OUT]
                                        [--markdown] [--fail-on-false-verified]

Defaults per platform: Windows System32 + SysWOW64 DLLs; Linux /usr/bin and the
multiarch /usr/lib/<triplet> ELF files; macOS /bin and /usr/bin Mach-O files.
"""

import glob
import hashlib
import json
import math
import os
import platform
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from reverify import __version__  # noqa: E402
from reverify.backends import backend_report  # noqa: E402
from reverify.binary import parse_binary  # noqa: E402
from reverify.verifier import Verifier, Claim, VERIFIED, REFUTED, INCONCLUSIVE  # noqa: E402

PRIOR = ["push", "mov"]  # the model's textbook frame-pointer prologue guess
MAX_SIZE = 8 * 1024 * 1024
MAGICS = (b"MZ", b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe",
          b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce")


def default_dirs():
    if sys.platform.startswith("win"):
        cands = [r"C:\Windows\System32", r"C:\Windows\SysWOW64"]
    elif sys.platform == "darwin":
        cands = ["/bin", "/usr/bin"]
    else:
        cands = ["/usr/bin", "/usr/lib/x86_64-linux-gnu", "/usr/lib/aarch64-linux-gnu", "/lib/x86_64-linux-gnu"]
    return [d for d in cands if os.path.isdir(d)]


def is_binary(path):
    try:
        size = os.path.getsize(path)
        if not (0 < size < MAX_SIZE) or not os.path.isfile(path):
            return False
        with open(path, "rb") as f:
            head = f.read(4)
    except OSError:
        return False
    return any(head.startswith(m[: len(head)]) for m in MAGICS) and len(head) == 4


def sample(paths, n):
    """A deterministic spread across the sorted list (no RNG, reproducible)."""
    paths = sorted(paths)
    if len(paths) <= n:
        return paths
    step = len(paths) / n
    return [paths[int(i * step)] for i in range(n)]


def corpus(dirs, per_dir):
    out = []
    for d in dirs:
        pattern = "*.dll" if sys.platform.startswith("win") and d.lower().startswith(r"c:\windows") else "*"
        files = [p for p in glob.glob(os.path.join(d, pattern)) if is_binary(p)]
        out += sample(files, per_dir)
    return out


def wilson_upper(k, n, z=1.96):
    """Upper bound of the 95% Wilson interval for a rate k/n (0/n -> about 3/n for large n)."""
    if n <= 0:
        return None
    p = k / n
    denom = 1 + z * z / n
    centre = p + z * z / (2 * n)
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return min(1.0, (centre + margin) / denom)


def run(dirs, per_dir=12):
    dirs = dirs or default_dirs()
    rows, inconclusive = [], []
    for path in corpus(dirs, per_dir):
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError:
            continue
        info = parse_binary(data)
        if info.format not in ("PE", "ELF", "MachO") or not info.entrypoint:
            continue
        arch = info.arch if info.arch in ("x86", "x86_64", "arm", "arm64") else ("x86_64" if info.bits == 64 else "x86")
        v = Verifier(data)
        r1 = v.verify(Claim("instructions", {"offset": info.entrypoint, "space": "rva", "mnemonics": PRIOR, "arch": arch}))
        record = {
            "file": os.path.basename(path),
            "dir": os.path.dirname(path),
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "format": info.format,
            "arch": arch,
            "entry": hex(info.entrypoint),
        }
        if r1["verdict"] == INCONCLUSIVE:
            inconclusive.append({**record, "reason": r1["detail"]})
            continue
        actual = r1["evidence"].get("actual_mnemonics", [])
        false_verified = r1["verdict"] == VERIFIED and actual[:2] != PRIOR
        r2 = (v.verify(Claim("instructions", {"offset": info.entrypoint, "space": "rva", "mnemonics": actual[:4], "arch": arch}))
              if actual else {"verdict": INCONCLUSIVE})
        rows.append({
            **record,
            "prior_verdict": r1["verdict"],
            "actual_entry": actual[:4],
            "false_verified": false_verified,
            "recovered": r2["verdict"] == VERIFIED,
        })

    tested = len(rows)
    wrong = sum(1 for r in rows if r["prior_verdict"] == REFUTED)
    fv = sum(1 for r in rows if r["false_verified"])
    rec = sum(1 for r in rows if r["recovered"])
    engines = {k: v for k, v in backend_report().items() if k != "install_hint"}
    return {
        "schema": 1,
        "benchmark": "prologue_prior",
        "prior": PRIOR,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "environment": {
            "reverify": __version__,
            "python": platform.python_version(),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "engines": engines,
        },
        "corpus": {"dirs": dirs, "per_dir": per_dir, "sampling": "sorted, fixed stride"},
        "rows": rows,
        "inconclusive": inconclusive,
        "totals": {
            "tested": tested,
            "prior_wrong": wrong,
            "false_verified": fv,
            "recovered_after_1_round": rec,
            "inconclusive": len(inconclusive),
            "false_verified_rate_upper95": wilson_upper(fv, tested),
        },
    }


def print_console(result):
    rows, t = result["rows"], result["totals"]
    if not rows:
        print("no binaries with a decodable entry point found (need real binaries + capstone/lief)")
        for x in result["inconclusive"][:5]:
            print(f"  inconclusive: {x['file']}: {x['reason']}")
        return
    print(f"{'binary':30}{'arch':7}{'R1 prior':10}{'R2 fixed':10}entry[:3]")
    for r in rows:
        print(f"{r['file'][:29]:30}{r['arch']:7}{r['prior_verdict']:10}{'VERIFIED' if r['recovered'] else 'no':10}{','.join(r['actual_entry'][:3])}")
    print("\n==== results ====")
    print(f"binaries tested                 : {t['tested']}  (inconclusive, not counted: {t['inconclusive']})")
    print(f"prior wrong (hallucination rate): {t['prior_wrong']}/{t['tested']} = {round(100 * t['prior_wrong'] / t['tested'])}%")
    print(f"false VERIFIED (must be 0)       : {t['false_verified']}"
          f"   (95% upper bound on the rate: {100 * t['false_verified_rate_upper95']:.1f}%)")
    print(f"true bytes after 1 feedback round: {t['recovered_after_1_round']}/{t['tested']} = {round(100 * t['recovered_after_1_round'] / t['tested'])}%")
    env = result["environment"]
    print(f"environment: reverify {env['reverify']}, python {env['python']}, {env['platform']}, "
          f"disasm={env['engines']['disassembly']['engine']}, parse={env['engines']['binary_parsing']['engine']}")


def markdown(result):
    t, env = result["totals"], result["environment"]
    lines = [
        f"### prologue_prior — {env['platform']} ({env['machine']}), reverify {env['reverify']}, python {env['python']}",
        "",
        "| metric | value |",
        "|---|---|",
        f"| binaries tested | {t['tested']} (inconclusive, not counted: {t['inconclusive']}) |",
        f"| prior wrong (hallucination rate) | {t['prior_wrong']}/{t['tested']} |",
        f"| **false VERIFIED (must be 0)** | **{t['false_verified']}** (95% upper bound on the rate: "
        f"{100 * (t['false_verified_rate_upper95'] or 0):.1f}%) |",
        f"| true bytes after 1 feedback round | {t['recovered_after_1_round']}/{t['tested']} |",
        f"| engines | disasm={env['engines']['disassembly']['engine']}, parse={env['engines']['binary_parsing']['engine']} |",
        "",
        "| binary | arch | sha256 (12) | prior | entry | recovered |",
        "|---|---|---|---|---|---|",
    ]
    for r in result["rows"]:
        lines.append(f"| {r['file']} | {r['arch']} | `{r['sha256'][:12]}` | {r['prior_verdict']} | "
                     f"`{' '.join(r['actual_entry'][:3])}` | {'yes' if r['recovered'] else 'no'} |")
    if result["inconclusive"]:
        lines += ["", f"Inconclusive (not counted): " + ", ".join(f"{x['file']} ({x['reason'][:60]})" for x in result["inconclusive"][:8])]
    return "\n".join(lines)


def main(argv):
    per, out_json, want_md, gate = 12, None, False, False
    args = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--per-dir":
            per = int(argv[i + 1]); i += 2; continue
        if a == "--json":
            out_json = argv[i + 1]; i += 2; continue
        if a == "--markdown":
            want_md = True; i += 1; continue
        if a == "--fail-on-false-verified":
            gate = True; i += 1; continue
        args.append(a); i += 1
    result = run(args, per)
    if want_md:
        print(markdown(result))
    else:
        print_console(result)
    if out_json:
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=1)
        print(f"\nwrote {out_json}", file=sys.stderr)
    t = result["totals"]
    if gate:
        if t["tested"] == 0:
            print("GATE: nothing tested (no decodable binaries / engines missing)", file=sys.stderr)
            return 3
        if t["false_verified"]:
            print(f"GATE FAILED: {t['false_verified']} false VERIFIED", file=sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
