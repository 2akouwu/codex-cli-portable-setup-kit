#!/usr/bin/env python3
"""Balanced verifier benchmark: known-true and known-false claims of every kind, on real binaries.

The prologue benchmark probes one model prior. This one measures the verifier itself the
way a classifier is measured: for every binary in the corpus and every claim kind, it
builds one claim that is *known true* (derived from the bytes or the parsed tables) and one
that is *known false* (a controlled mutation that provably does not hold), asks the
verifier, and tallies a confusion matrix per kind:

- TP  known-true claim  -> VERIFIED
- FN  known-true claim  -> REFUTED        (a miss: must be 0 for byte-level kinds)
- FP  known-false claim -> VERIFIED       (the safety failure: must be 0 for every kind)
- TN  known-false claim -> REFUTED
- UNK either            -> INCONCLUSIVE   (honest "cannot judge", e.g. no engine installed)

Ground truth: byte-level kinds come from the raw bytes themselves (independent of any
reader); structural kinds from the parsed tables (the pure parser is checked against lief
elsewhere); ``instructions`` from the disassembler (checked against capstone, objdump and
hand-verified vectors elsewhere); ``function_at`` from the export table (independent of the
analysis engine). Deterministic: offsets are drawn from an RNG seeded by each file's SHA-256.

Usage:
    python benchmarks/verifier_matrix.py [dir ...] [--per-dir N] [--json OUT] [--markdown]
                                         [--fail-on-false-verified]
"""

import hashlib
import json
import os
import platform
import random
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, HERE)
from reverify import __version__  # noqa: E402
from reverify.backends import backend_report  # noqa: E402
from reverify.binary import parse_binary  # noqa: E402
from reverify.disasm import Disassembler, UnsupportedArch, PSEUDO_MNEMONICS, pattern_scan  # noqa: E402
from reverify.verifier import Verifier, Claim, VERIFIED, REFUTED, INCONCLUSIVE  # noqa: E402
from prologue_prior import default_dirs, corpus, wilson_upper  # noqa: E402

BYTE_KINDS = ("bytes_at", "u32_at", "u64_at", "string_present", "pattern_present")
STRUCT_KINDS = ("section_present", "import_present", "export_present")
KINDS = BYTE_KINDS + STRUCT_KINDS + ("instructions", "function_at")


def _flip(hexstr):
    b = bytearray(bytes.fromhex(hexstr))
    b[0] ^= 0x01
    return b.hex()


def claims_for(data, info, rng):
    """Yield (kind, true_claim_params, false_claim_params); None params = kind not applicable."""
    n = len(data)
    if n < 64:
        return
    off = rng.randint(0, n - 16)
    # -- byte-level: ground truth is the bytes ---------------------------------
    exp = data[off : off + 8].hex()
    yield "bytes_at", {"offset": off, "expected": exp}, {"offset": off, "expected": _flip(exp)}
    v32 = int.from_bytes(data[off : off + 4], "little")
    yield "u32_at", {"offset": off, "expected": v32}, {"offset": off, "expected": (v32 + 1) & 0xFFFFFFFF}
    v64 = int.from_bytes(data[off : off + 8], "little")
    yield "u64_at", {"offset": off, "expected": v64}, {"offset": off, "expected": (v64 + 1) & 0xFFFFFFFFFFFFFFFF}
    strings = [m.group().decode("latin1") for m in re.finditer(rb"[A-Za-z][A-Za-z0-9_.]{7,31}", data[: 1 << 20])]
    if strings:
        s = strings[rng.randrange(len(strings))]
        bad = None
        for _ in range(8):
            cand = s[:-1] + chr(rng.randint(0x23, 0x7A))
            if cand.encode("latin1") not in data:
                bad = cand
                break
        if bad:
            yield "string_present", {"value": s}, {"value": bad}
    pat = list(data[off : off + 8])
    if any(pat):
        toks = [f"{b:02x}" for b in pat]
        toks[3] = "??"
        good = " ".join(toks)
        bad = None
        for _ in range(8):
            mut = list(toks)
            for i in (0, 1, 5, 6):
                mut[i] = f"{rng.randint(0, 255):02x}"
            cand = " ".join(mut)
            if not pattern_scan(data, cand):
                bad = cand
                break
        if bad:
            yield "pattern_present", {"pattern": good}, {"pattern": bad}
    # -- structural: ground truth is the parsed tables ---------------------------
    if info.format in ("PE", "ELF", "MachO") and not info.error:
        secs = [s for s in info.sections if s.name and s.virtual_address]
        if secs:
            s = secs[rng.randrange(len(secs))]
            yield "section_present", {"name": s.name, "virtual_address": s.virtual_address}, \
                {"name": s.name, "virtual_address": s.virtual_address + 0x10}
        pairs = [(lib, f) for lib, fns in info.imports.items() for f in fns if f and not f.startswith("Ordinal_")]
        if pairs:
            lib, f = pairs[rng.randrange(len(pairs))]
            good = {"function": f, "lib": lib} if info.format == "PE" and lib != "*" else {"function": f}
            yield "import_present", good, {"function": f"Reverify_NoSuchImport_{rng.randint(0, 9999)}"}
        if info.exports:
            e = info.exports[rng.randrange(len(info.exports))]
            yield "export_present", {"name": e}, {"name": f"Reverify_NoSuchExport_{rng.randint(0, 9999)}"}
        # -- instructions at the entry point: ground truth is the disassembler --------
        if info.entrypoint is not None:
            arch = info.arch if info.arch in ("x86", "x86_64", "arm", "arm64") else "x86_64"
            eoff = info.rva_to_offset(info.entrypoint) if info.format != "ELF" else info.rva_to_offset(info.entrypoint)
            if eoff is not None and eoff + 16 <= n:
                try:
                    insns = Disassembler(arch=arch).disassemble(data[eoff : eoff + 64], base_address=0x1000)
                except UnsupportedArch:
                    insns = []
                mnems = [i.mnemonic.lower() for i in insns[:3]]
                if len(mnems) == 3 and not any(m in PSEUDO_MNEMONICS for m in mnems):
                    wrong = "int3" if "int3" not in mnems else "hlt"
                    yield "instructions", {"offset": info.entrypoint, "space": "rva", "arch": arch, "mnemonics": mnems}, \
                        {"offset": info.entrypoint, "space": "rva", "arch": arch, "mnemonics": [wrong] + mnems[1:]}
        # -- function_at: ground truth is the export table (independent of the engine) --
        if info.export_rvas:
            name, rva = sorted(info.export_rvas.items())[rng.randrange(len(info.export_rvas))]
            yield "function_at", {"offset": rva, "space": "rva"}, {"offset": rva + 3, "space": "rva"}


def run(dirs, per_dir=25):
    dirs = dirs or default_dirs()
    counts = {k: {"n": 0, "TP": 0, "FN": 0, "UNK_true": 0, "FP": 0, "TN": 0, "UNK_false": 0} for k in KINDS}
    rows, fps, fns = [], [], []
    for path in corpus(dirs, per_dir):
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError:
            continue
        sha = hashlib.sha256(data).hexdigest()
        rng = random.Random(int(sha[:16], 16))
        info = parse_binary(data)
        v = Verifier(data)
        for kind, good, bad in claims_for(data, info, rng):
            rt = v.verify(Claim(kind, good))["verdict"]
            rf = v.verify(Claim(kind, bad))["verdict"]
            c = counts[kind]
            c["n"] += 1
            if rt == VERIFIED:
                c["TP"] += 1
            elif rt == REFUTED:
                c["FN"] += 1
                fns.append({"file": os.path.basename(path), "sha256": sha, "kind": kind, "claim": good})
            else:
                c["UNK_true"] += 1
            if rf == VERIFIED:
                c["FP"] += 1
                fps.append({"file": os.path.basename(path), "sha256": sha, "kind": kind, "claim": bad})
            elif rf == REFUTED:
                c["TN"] += 1
            else:
                c["UNK_false"] += 1
            rows.append({"file": os.path.basename(path), "sha256": sha, "format": info.format, "kind": kind,
                         "true_claim": rt, "false_claim": rf})
    total_false = sum(c["n"] for c in counts.values())
    total_fp = sum(c["FP"] for c in counts.values())
    engines = {k: v for k, v in backend_report().items() if k != "install_hint"}
    return {
        "schema": 1,
        "benchmark": "verifier_matrix",
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "environment": {"reverify": __version__, "python": platform.python_version(),
                        "platform": platform.platform(), "machine": platform.machine(), "engines": engines},
        "corpus": {"dirs": dirs, "per_dir": per_dir, "binaries": len({r["sha256"] for r in rows})},
        "per_kind": counts,
        "totals": {
            "claims_true": total_false, "claims_false": total_false,
            "false_verified": total_fp,
            "false_verified_rate_upper95": wilson_upper(total_fp, total_false),
            "missed_true_byte_level": sum(counts[k]["FN"] for k in BYTE_KINDS + STRUCT_KINDS),
        },
        "false_verified": fps,
        "missed_true": fns,
        "rows": rows,
    }


def markdown(result):
    e, t = result["environment"], result["totals"]
    lines = [
        f"### verifier_matrix — {e['platform']} ({e['machine']}), reverify {e['reverify']}, python {e['python']}, "
        f"{result['corpus']['binaries']} binaries",
        "",
        "| kind | n | TP | FN | unk(true) | **FP** | TN | unk(false) |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for k, c in result["per_kind"].items():
        if c["n"]:
            lines.append(f"| {k} | {c['n']} | {c['TP']} | {c['FN']} | {c['UNK_true']} | **{c['FP']}** | {c['TN']} | {c['UNK_false']} |")
    lines += ["",
              f"**false VERIFIED: {t['false_verified']} of {t['claims_false']} known-false claims** "
              f"(95% upper bound {100 * (t['false_verified_rate_upper95'] or 0):.1f}%); "
              f"missed known-true byte/structural claims: {t['missed_true_byte_level']}"]
    if result["false_verified"]:
        lines += ["", "False VERIFIED cases:"] + [f"- {x['file']} {x['kind']} {json.dumps(x['claim'])}" for x in result["false_verified"][:10]]
    if result["missed_true"]:
        lines += ["", "Missed known-true claims:"] + [f"- {x['file']} {x['kind']} {json.dumps(x['claim'])[:120]}" for x in result["missed_true"][:10]]
    return "\n".join(lines)


def main(argv):
    per, out_json, want_md, gate, args = 25, None, False, False, []
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
    print(markdown(result))
    if out_json:
        slim = dict(result)
        slim["rows"] = result["rows"]
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(slim, f, indent=1)
        print(f"\nwrote {out_json}", file=sys.stderr)
    t = result["totals"]
    if gate:
        if t["claims_false"] == 0:
            print("GATE: nothing tested", file=sys.stderr)
            return 3
        if t["false_verified"]:
            print(f"GATE FAILED: {t['false_verified']} false VERIFIED", file=sys.stderr)
            return 2
        if t["missed_true_byte_level"]:
            print(f"GATE FAILED: {t['missed_true_byte_level']} known-true byte/structural claims refuted", file=sys.stderr)
            return 4
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
