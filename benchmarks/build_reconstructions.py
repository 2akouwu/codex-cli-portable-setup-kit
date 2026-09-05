#!/usr/bin/env python3
"""Generate the reconstruction re-executability corpus (``corpus/reconstructions.jsonl``).

Each record is a small function with a **reference implementation** and two candidate
"reconstructions": one faithful (labelled ``correct``) and one with a plausible decompilation
mistake (labelled ``wrong``) — a flipped operator, min vs max, the wrong shift amount, a
rounding bug. Both C and Python are emitted, so the same corpus measures re-executability with
a compiler (the decompilation-relevant case) and without one (runs on every platform).

The benchmark (``reconstructions.py``) runs each candidate against its reference through
``functions_equiv`` and checks: a faithful reconstruction VERIFIES, a wrong one is REFUTED with
a witness, and **no wrong reconstruction is ever accepted** (0 false accepts). This is the
ExeBench / LLM4Decompile re-executability methodology on a corpus anyone can read and extend;
point the same runner at those datasets (the format matches) for their published numbers.

Rebuild: ``python benchmarks/build_reconstructions.py`` (deterministic; commit the result).
"""
from __future__ import annotations

import json
import os

C_HEAD = "#include <stdio.h>\n#include <stdlib.h>\n"


def c_prog(expr: str, nargs: int) -> str:
    reads = "".join(f"long x{i}=atol(v[{i + 1}]);" for i in range(nargs))
    return C_HEAD + f"int main(int c,char**v){{{reads}printf(\"%ld\",(long)({expr}));return 0;}}"


def py_prog(expr: str, nargs: int) -> str:
    reads = "; ".join(f"x{i}=int(sys.argv[{i + 1}])" for i in range(nargs))
    return f"import sys\n{reads}\nprint(int({expr}))"


# spec: name, category, nargs, {reference,correct,wrong} -> (c_expr, py_expr)
# variables are x0, x1, ...; keep expressions int64-safe for unsigned 32-bit inputs.
SPECS = [
    ("add", "arithmetic", 2, ("x0+x1", "x0+x1"), ("x1+x0", "x1+x0"), ("x0-x1", "x0-x1")),
    ("sub", "arithmetic", 2, ("x0-x1", "x0-x1"), ("-(x1-x0)", "-(x1-x0)"), ("x1-x0", "x1-x0")),
    ("avg_floor", "rounding", 2, ("(x0+x1)/2", "(x0+x1)//2"), ("(x0+x1)>>1", "(x0+x1)>>1"),
     ("x0/2+x1/2", "x0//2+x1//2")),   # wrong: loses the low-bit carry when both are odd
    ("bxor", "bitwise", 2, ("x0^x1", "x0^x1"), ("x1^x0", "x1^x0"), ("x0&x1", "x0&x1")),
    ("band", "bitwise", 2, ("x0&x1", "x0&x1"), ("x1&x0", "x1&x0"), ("x0|x1", "x0|x1")),
    ("bor", "bitwise", 2, ("x0|x1", "x0|x1"), ("x1|x0", "x1|x0"), ("x0^x1", "x0^x1")),
    ("max2", "control-flow", 2, ("x0>x1?x0:x1", "(x0 if x0>x1 else x1)"),
     ("x1>x0?x1:x0", "(x1 if x1>x0 else x0)"), ("x0<x1?x0:x1", "(x0 if x0<x1 else x1)")),
    ("min2", "control-flow", 2, ("x0<x1?x0:x1", "(x0 if x0<x1 else x1)"),
     ("x1<x0?x1:x0", "(x1 if x1<x0 else x0)"), ("x0>x1?x0:x1", "(x0 if x0>x1 else x1)")),
    ("shl_lo", "bitwise", 2, ("(x0 & 0xffff) << (x1 & 15)", "(x0 & 0xffff) << (x1 & 15)"),
     ("(x0 & 0xffff) << (x1 % 16)", "(x0 & 0xffff) << (x1 % 16)"),
     ("(x0 & 0xffff) << (x1 & 31)", "(x0 & 0xffff) << (x1 & 31)")),   # wrong: unmasked-ish shift amount
    ("hi16", "field-extract", 1, ("(x0 >> 16) & 0xffff", "(x0 >> 16) & 0xffff"),
     ("(x0 & 0xffff0000) >> 16", "(x0 & 0xffff0000) >> 16"), ("x0 & 0xffff", "x0 & 0xffff")),
    ("lo16", "field-extract", 1, ("x0 & 0xffff", "x0 & 0xffff"),
     ("x0 - ((x0 >> 16) << 16)", "x0 - ((x0 >> 16) << 16)"), ("(x0 >> 16) & 0xffff", "(x0 >> 16) & 0xffff")),
    ("is_even", "predicate", 1, ("(x0 & 1)==0 ? 1 : 0", "(1 if (x0 & 1)==0 else 0)"),
     ("1 - (x0 & 1)", "1 - (x0 & 1)"), ("x0 & 1", "x0 & 1")),   # wrong: returns is_odd
]


def build():
    records = []
    for name, cat, nargs, ref, correct, wrong in SPECS:
        records.append({
            "name": name,
            "category": cat,
            "nargs": nargs,
            "reference": {"c": c_prog(ref[0], nargs), "python": py_prog(ref[1], nargs)},
            "candidates": [
                {"label": "correct", "note": "faithful reconstruction (different form, same behaviour)",
                 "c": c_prog(correct[0], nargs), "python": py_prog(correct[1], nargs)},
                {"label": "wrong", "note": "plausible decompilation mistake",
                 "c": c_prog(wrong[0], nargs), "python": py_prog(wrong[1], nargs)},
            ],
        })
    out = os.path.join(os.path.dirname(__file__), "corpus", "reconstructions.jsonl")
    with open(out, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"wrote {len(records)} records ({sum(len(r['candidates']) for r in records)} candidates) -> {out}")


if __name__ == "__main__":
    build()
