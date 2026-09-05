#!/usr/bin/env python3
"""Re-executability scorecard over a standard decompilation dataset.

The hallucination scorecard (``hallucination_probes.py``) measures *false
accepts* on real binaries. This one measures the other axis the field reports —
**executable correctness** of a reconstruction — over a dataset in the shape used
by ExeBench / LLM4Decompile: for each item a candidate C program and a set of
recorded input/output pairs. reverify compiles each candidate and re-runs it
against the I/O (the ``exebench`` verifier path), so "correct" means *it produced
the recorded outputs*, not *it looks right*.

Point your own dataset at it and you get numbers comparable to the published
re-executability metric, produced by the same tool that guarantees a mismatch is
a refutation with a witness — not a subjective read.

Dataset format — a JSON array, or JSON Lines (one object per line). Each record:

    {
      "name": "add",
      "candidate_c": "int main(int c,char**v){...printf(\\"%d\\", a+b);}",
      "test_cases": [{"input": [2, 3], "expected": 5}, [ [4,4], 8 ]],
      "label": "correct"        # optional: "correct" | "wrong" (enables the
                                # confusion check: a wrong candidate must be REFUTED,
                                # never re-executable — 0 false accepts)
    }

``candidate_c`` may also be ``c_source`` / ``source`` / ``candidate``;
``test_cases`` may also be ``io_pairs`` (``[[input, expected], ...]``).

Usage::

    REVERIFY_ALLOW_NATIVE_EXEC=1 python benchmarks/reexec_dataset.py dataset.jsonl [--cc gcc] [--json]

Native execution is off unless ``REVERIFY_ALLOW_NATIVE_EXEC=1`` (compile + run are
sandboxed by ``reverify.sandbox``); without it every record is ``inconclusive``
and the scorecard says so honestly rather than inventing a number.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Callable, Dict, List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from reverify.exebench import exebench_verify, native_exec_allowed, has_compiler  # noqa: E402

_SOURCE_KEYS = ("candidate_c", "c_source", "source", "candidate")


def candidate_source(rec: Dict[str, Any]) -> Optional[str]:
    for key in _SOURCE_KEYS:
        val = rec.get(key)
        if isinstance(val, str) and val.strip():
            return val
    return None


def load_dataset(path: str) -> List[Dict[str, Any]]:
    """Load a JSON array or JSON-Lines file into a list of records."""
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    text_stripped = text.lstrip()
    if text_stripped.startswith("["):
        data = json.loads(text)
        if not isinstance(data, list):
            raise ValueError("top-level JSON must be an array of records")
        return [r for r in data if isinstance(r, dict)]
    records: List[Dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("//") or line.startswith("#"):
            continue
        obj = json.loads(line)
        if isinstance(obj, dict):
            records.append(obj)
    return records


def _default_verify(cc: str) -> Callable[[Dict[str, Any], str], str]:
    def verify(record: Dict[str, Any], c_source: str) -> str:
        return exebench_verify(record, c_source, cc=cc)["status"]
    return verify


def score_records(
    records: List[Dict[str, Any]],
    *,
    cc: str = "gcc",
    verify: Optional[Callable[[Dict[str, Any], str], str]] = None,
) -> Dict[str, Any]:
    """Run every record through the exebench path; aggregate the scorecard.

    ``verify(record, c_source) -> "pass"|"fail"|"inconclusive"`` is injectable so
    the aggregation is testable without a compiler; the default compiles and runs.
    """
    verify = verify or _default_verify(cc)
    total = len(records)
    reexecutable = refuted = inconclusive = no_source = 0
    labeled = false_accepts = missed = 0
    false_accept_items: List[str] = []
    for rec in records:
        name = str(rec.get("name", "?"))
        src = candidate_source(rec)
        if src is None:
            no_source += 1
            inconclusive += 1
            continue
        status = verify(rec, src)
        if status == "pass":
            reexecutable += 1
        elif status == "fail":
            refuted += 1
        else:
            inconclusive += 1
        label = str(rec.get("label", "")).lower()
        if label in ("correct", "wrong"):
            labeled += 1
            if label == "wrong" and status == "pass":
                false_accepts += 1               # must stay 0
                false_accept_items.append(name)
            elif label == "correct" and status == "fail":
                missed += 1
    decisive = reexecutable + refuted
    return {
        "total": total,
        "reexecutable": reexecutable,
        "refuted": refuted,
        "inconclusive": inconclusive,
        "no_source": no_source,
        "reexec_rate": (reexecutable / decisive) if decisive else None,
        "labeled": labeled,
        "false_accepts": false_accepts,
        "false_accept_items": false_accept_items,
        "missed_correct": missed,
    }


def format_report(summary: Dict[str, Any]) -> str:
    lines = [
        "== re-executability scorecard ==",
        f"records          : {summary['total']}",
        f"re-executable    : {summary['reexecutable']}  (compiled and matched all recorded I/O)",
        f"refuted          : {summary['refuted']}  (a recorded case did not match — with a witness)",
        f"inconclusive     : {summary['inconclusive']}"
        + (f"  ({summary['no_source']} had no candidate source)" if summary["no_source"] else ""),
    ]
    if summary["reexec_rate"] is not None:
        lines.append(f"re-exec rate     : {summary['reexec_rate'] * 100:.1f}%  (of {summary['reexecutable'] + summary['refuted']} decided)")
    if summary["labeled"]:
        lines.append("")
        lines.append(f"labeled          : {summary['labeled']}")
        lines.append(f"false accepts    : {summary['false_accepts']}  (labeled wrong but passed — MUST be 0)"
                     + (f"  -> {', '.join(summary['false_accept_items'])}" if summary["false_accept_items"] else ""))
        lines.append(f"missed correct   : {summary['missed_correct']}  (labeled correct but refuted)")
    return "\n".join(lines)


def run(path: str, *, cc: str = "gcc", as_json: bool = False) -> int:
    records = load_dataset(path)
    if not native_exec_allowed():
        note = ("native execution is off; set REVERIFY_ALLOW_NATIVE_EXEC=1 to actually compile and run "
                f"(every one of the {len(records)} records is inconclusive until then)")
    elif not has_compiler(cc):
        note = f"no C compiler '{cc}' on PATH; records are inconclusive"
    else:
        note = None
    summary = score_records(records, cc=cc)
    if as_json:
        print(json.dumps({"summary": summary, "note": note}, indent=2, ensure_ascii=False))
    else:
        if note:
            print(f"note: {note}\n")
        print(format_report(summary))
    # non-zero exit if any wrong candidate slipped through as re-executable
    return 1 if summary["false_accepts"] else 0


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    as_json = "--json" in argv
    argv = [a for a in argv if a != "--json"]
    cc = "gcc"
    if "--cc" in argv:
        i = argv.index("--cc")
        cc = argv[i + 1] if i + 1 < len(argv) else "gcc"
        del argv[i:i + 2]
    paths = [a for a in argv if not a.startswith("--")]
    if not paths:
        print(__doc__)
        return 2
    return run(paths[0], cc=cc, as_json=as_json)


if __name__ == "__main__":
    sys.exit(main())
