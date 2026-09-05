#!/usr/bin/env python3
"""Re-executability scorecard over the reconstruction corpus (``corpus/reconstructions.jsonl``).

For every candidate reconstruction, run it against its reference implementation through
``functions_equiv`` (compile/interpret both, run over shared inputs, compare) and tally, per
language:

- **re-executable** — a *correct* candidate that VERIFIES (matched the reference);
- **refuted**       — a *wrong* candidate that is REFUTED (a witness input where it differs);
- **false accepts** — a *wrong* candidate that slipped through as re-executable. **Must be 0.**
- **missed**        — a *correct* candidate the tool refuted (over-strict).

This is the ExeBench / LLM4Decompile re-executability metric on a corpus anyone can read; the
point reverify adds is that a mismatch is a *refutation with a witness*, and the gate below
fails the build on a single false accept.

Usage::

    REVERIFY_ALLOW_NATIVE_EXEC=1 python benchmarks/reconstructions.py [--lang c|python|all]
        [--cc gcc] [--json out.json] [--markdown] [--fail-on-false-accept]

Native execution is off unless ``REVERIFY_ALLOW_NATIVE_EXEC=1`` (compile and run are sandboxed);
without it every candidate is inconclusive and the scorecard says so.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from reverify.exebench import functions_equiv_verify, native_exec_allowed, has_compiler  # noqa: E402

CORPUS = os.path.join(os.path.dirname(__file__), "corpus", "reconstructions.jsonl")

# Inputs that actually exercise the differences: asymmetric pairs (x0 != x1, so a swapped or
# min/max flip shows), odd values (rounding), varied shift amounts and bit fields. A wrong
# reconstruction must differ from the reference on at least one of these.
_INPUTS_2 = [(3, 5), (5, 3), (1, 2), (2, 1), (0, 7), (7, 0), (9, 4), (255, 17), (65535, 3),
             (0x0f0f, 0x00ff), (0x12345678, 20), (0xffff0000, 16), (0xdeadbeef, 3), (1, 0)]
_INPUTS_1 = [(3,), (255,), (0x1234,), (0x8000,), (1,), (0xffffffff,), (0x10000,), (7,), (0xabcd,), (2,)]


def bench_inputs(nargs: int) -> List[tuple]:
    return _INPUTS_2 if nargs == 2 else _INPUTS_1


def load(path: str = CORPUS) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def score(records: List[Dict[str, Any]], lang: str, *, cc: str = "gcc",
          max_inputs: int = 40) -> Dict[str, Any]:
    reexec = refuted = false_accept = missed = inconclusive = candidates = 0
    false_items: List[str] = []
    for rec in records:
        reference = rec.get("reference", {}).get(lang)
        if not reference:
            continue
        for cand in rec.get("candidates", []):
            code = cand.get(lang)
            if not code:
                continue
            candidates += 1
            nargs = int(rec.get("nargs", 2))
            res = functions_equiv_verify(code, reference=reference, lang=lang, nargs=nargs,
                                         inputs=bench_inputs(nargs), cc=cc, max_inputs=max_inputs)
            status, label = res["status"], cand.get("label")
            if status == "inconclusive":
                inconclusive += 1
            elif label == "correct":
                if status == "pass":
                    reexec += 1
                else:
                    missed += 1
            elif label == "wrong":
                if status == "fail":
                    refuted += 1
                elif status == "pass":
                    false_accept += 1
                    false_items.append(f"{rec['name']}:{lang}")
    decided = reexec + refuted + false_accept + missed
    return {
        "lang": lang, "candidates": candidates, "reexecutable": reexec, "refuted": refuted,
        "false_accepts": false_accept, "false_accept_items": false_items, "missed": missed,
        "inconclusive": inconclusive,
        "reexec_rate": (reexec / (reexec + missed)) if (reexec + missed) else None,
        "refute_rate": (refuted / (refuted + false_accept)) if (refuted + false_accept) else None,
    }


def format_markdown(summaries: List[Dict[str, Any]]) -> str:
    lines = ["### Reconstruction re-executability (`benchmarks/reconstructions.py`)", "",
             "| lang | candidates | re-executable | refuted | false accepts | missed | inconclusive |",
             "|------|-----------:|--------------:|--------:|--------------:|-------:|-------------:|"]
    for s in summaries:
        lines.append(f"| {s['lang']} | {s['candidates']} | {s['reexecutable']} | {s['refuted']} | "
                     f"**{s['false_accepts']}** | {s['missed']} | {s['inconclusive']} |")
    lines.append("")
    lines.append("_A correct reconstruction should re-execute; a wrong one should be refuted; "
                 "**false accepts must be 0**._")
    return "\n".join(lines)


def format_text(summaries: List[Dict[str, Any]]) -> str:
    out = ["== reconstruction re-executability =="]
    for s in summaries:
        out.append(f"[{s['lang']}] candidates={s['candidates']}  re-executable={s['reexecutable']}  "
                   f"refuted={s['refuted']}  false_accepts={s['false_accepts']}  missed={s['missed']}  "
                   f"inconclusive={s['inconclusive']}")
        if s["false_accept_items"]:
            out.append("   false accepts: " + ", ".join(s["false_accept_items"]))
    return "\n".join(out)


def run(langs: List[str], *, cc: str = "gcc", as_json: Optional[str] = None,
        markdown: bool = False, fail_on_false_accept: bool = False, max_inputs: int = 40) -> int:
    records = load()
    note = None
    if not native_exec_allowed():
        note = "native execution off; set REVERIFY_ALLOW_NATIVE_EXEC=1 (every candidate is inconclusive until then)"
    summaries = [score(records, lang, cc=cc, max_inputs=max_inputs) for lang in langs]
    if note and not markdown:
        print(f"note: {note}\n")
    print(format_markdown(summaries) if markdown else format_text(summaries))
    total_false = sum(s["false_accepts"] for s in summaries)
    if as_json:
        with open(as_json, "w", encoding="utf-8") as f:
            json.dump({"records": len(records), "summaries": summaries, "note": note}, f, indent=2)
    if fail_on_false_accept and total_false:
        print(f"\nFAIL: {total_false} wrong reconstruction(s) accepted as re-executable", file=sys.stderr)
        return 1
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    markdown = "--markdown" in argv
    fail = "--fail-on-false-accept" in argv
    lang = "all"
    cc = "gcc"
    as_json = None
    i = 0
    rest = [a for a in argv if a not in ("--markdown", "--fail-on-false-accept")]
    while i < len(rest):
        if rest[i] == "--lang" and i + 1 < len(rest):
            lang = rest[i + 1]; i += 2; continue
        if rest[i] == "--cc" and i + 1 < len(rest):
            cc = rest[i + 1]; i += 2; continue
        if rest[i] == "--json" and i + 1 < len(rest):
            as_json = rest[i + 1]; i += 2; continue
        i += 1
    langs = ["c", "python"] if lang == "all" else [lang]
    return run(langs, cc=cc, as_json=as_json, markdown=markdown, fail_on_false_accept=fail)


if __name__ == "__main__":
    sys.exit(main())
