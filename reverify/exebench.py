#!/usr/bin/env python3
"""ExeBench / re-executability adapter for source-level reconstructions.

Complements the Unicorn path in ``behavior.py``. Where ``behavior_equiv`` runs
the original function bytes and a candidate byte sequence / expression, this
adapter compiles a *candidate C program* and re-runs it against recorded input
/output (I/O) pairs — the executable-decompilation metric behind ExeBench
(LLM4Decompile): correctness is measured by execution, not by appearance.

Honest scope and labelling (kept consistent with ``behavior.py``):

- **This runs native code.** Unlike ``emulate_result`` / ``behavior_equiv`` (Unicorn
  emulation) the candidate is compiled and executed on the host, so a claim's
  ``c_source`` is arbitrary code. The adapter is therefore **off by default**:
  it returns ``inconclusive`` unless the environment opts in with
  ``REVERIFY_ALLOW_NATIVE_EXEC=1`` (never enable it for an MCP server exposed to
  untrusted agents without a sandbox).
- The candidate C is compiled with a C compiler. The whole adapter is *gated*:
  if no compiler is available it returns ``inconclusive`` rather than failing.
- I/O contract: each test case passes its inputs to the program as command-line
  arguments (decimal integers) and reads a single decimal integer from stdout.
  This is the minimal, tool-agnostic contract; a record may carry an ``iotype``
  for the runner to interpret (this default runner uses ``"argv"``).
- A *pass* means "passed N/N test cases (tested, not proven)"; a single
  mismatch is a definite refutation with the failing case as witness.

Usage (module level)::

    from reverify.exebench import exebench_verify
    rec = {"name": "add", "test_cases": [{"input": [2, 3], "expected": 5}]}
    exebench_verify(rec, "int main(int c,char**v){...return a+b...}")
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Sequence

NATIVE_EXEC_ENV = "REVERIFY_ALLOW_NATIVE_EXEC"
NATIVE_EXEC_HINT = (
    f"native execution of candidate C is off by default; set {NATIVE_EXEC_ENV}=1 in a trusted, "
    "sandboxed environment to enable it"
)


def native_exec_allowed() -> bool:
    """True when the environment has opted in to compiling and running candidate code."""
    return os.environ.get(NATIVE_EXEC_ENV, "").strip().lower() in ("1", "true", "yes", "on")


def has_compiler(cc: str = "gcc") -> bool:
    """True if the C compiler ``cc`` is on PATH."""
    return shutil.which(cc) is not None


def _to_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    return int(str(value), 0)


def compile_candidate(
    c_source: str,
    *,
    cc: str = "gcc",
    extra_flags: Optional[Sequence[str]] = None,
    timeout: int = 30,
    workdir: Optional[str] = None,
) -> Optional[str]:
    """Compile ``c_source`` to an executable; return the binary path or None.

    Gated: returns ``None`` when ``cc`` is absent or the compile fails. The
    source and output live in ``workdir`` (a fresh temp dir when omitted; the
    caller owns cleanup — ``exebench_verify`` uses a temporary directory that is
    removed afterwards).
    """
    if not has_compiler(cc):
        return None
    workdir = workdir or tempfile.mkdtemp(prefix="exebench.")
    src = os.path.join(workdir, "candidate.c")
    out = os.path.join(workdir, "candidate")
    with open(src, "w", encoding="utf-8") as f:
        f.write(c_source)
    cmd = [cc, "-O0", "-w", *list(extra_flags or []), "-o", out, src]
    try:
        subprocess.run(cmd, capture_output=True, timeout=timeout, check=False, cwd=workdir,
                       stdin=subprocess.DEVNULL)
    except (subprocess.TimeoutExpired, OSError):
        return None
    # MinGW / MSVC toolchains append .exe to the requested output name
    for cand in (out, out + ".exe"):
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def run_case(
    binary: str,
    input_args: Sequence[int],
    *,
    timeout: int = 10,
) -> Optional[int]:
    """Run ``binary`` with ``input_args`` as argv; parse one int from stdout."""
    try:
        proc = subprocess.run(
            [binary, *[str(a) for a in input_args]],
            capture_output=True,
            timeout=timeout,
            cwd=os.path.dirname(binary) or None,
            stdin=subprocess.DEVNULL,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    if proc.returncode != 0:
        return None
    text = proc.stdout.decode("utf-8", "ignore").strip()
    # take the first whitespace-separated token that parses as an integer
    for tok in text.split():
        try:
            return int(tok, 0)
        except ValueError:
            continue
    return None


def ExeBenchRecord(data: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize an ExeBench-format record (function + I/O test cases).

    Accepts ``{"name": str, "test_cases": [{"input": [...], "expected": int}]}``
    (the input may also be a single int; expected a string). Returns a normalized
    dict; raises ``ValueError`` on a malformed record.
    """
    cases_raw = data.get("test_cases") or data.get("io_pairs") or []
    cases: List[Dict[str, Any]] = []
    for i, raw in enumerate(cases_raw):
        if isinstance(raw, (list, tuple)):
            if len(raw) != 2:
                raise ValueError(f"test case {i}: I/O pair must have 2 elements")
            inp, exp = raw
        elif isinstance(raw, dict):
            if "input" not in raw or "expected" not in raw:
                raise ValueError(f"test case {i}: needs 'input' and 'expected'")
            inp, exp = raw["input"], raw["expected"]
        else:
            raise ValueError(f"test case {i}: unsupported shape {type(raw).__name__}")
        if isinstance(inp, (list, tuple)):
            inp = [int(x) for x in inp]
        else:
            inp = [int(inp)]
        cases.append({"input": inp, "expected": int(exp)})
    return {
        "name": str(data.get("name", "candidate")),
        "test_cases": cases,
    }


def _inconclusive(total: int, detail: str) -> Dict[str, Any]:
    return {"status": "inconclusive", "passed": 0, "total": total, "failures": [], "detail": detail}


def exebench_verify(
    record: Dict[str, Any],
    c_source: str,
    *,
    cc: str = "gcc",
    extra_flags: Optional[Sequence[str]] = None,
    timeout: int = 30,
) -> Dict[str, Any]:
    """Compile the candidate and check it against every I/O pair of ``record``.

    Returns ``{status, passed, total, failures, detail}`` where status is
    ``"pass"`` / ``"fail"`` / ``"inconclusive"``. A ``fail`` carries the first
    failing case as a concrete witness. Off unless ``REVERIFY_ALLOW_NATIVE_EXEC=1``.
    """
    rec = ExeBenchRecord(record)
    total = len(rec["test_cases"])
    if not rec["test_cases"]:
        return _inconclusive(0, "record has no test cases")
    if not native_exec_allowed():
        return _inconclusive(total, NATIVE_EXEC_HINT)
    if not has_compiler(cc):
        return _inconclusive(total, f"no C compiler '{cc}' available; cannot compile the candidate")
    with tempfile.TemporaryDirectory(prefix="exebench.") as workdir:
        binary = compile_candidate(c_source, cc=cc, extra_flags=extra_flags, timeout=timeout, workdir=workdir)
        if binary is None:
            return _inconclusive(total, "candidate did not compile (no compiler, or compile error)")
        failures: List[Dict[str, Any]] = []
        passed = 0
        for case in rec["test_cases"]:
            got = run_case(binary, case["input"], timeout=timeout)
            if got is None:
                failures.append({"input": case["input"], "expected": case["expected"], "got": None})
                continue
            if got != case["expected"]:
                failures.append({"input": case["input"], "expected": case["expected"], "got": got})
            else:
                passed += 1
    if failures:
        return {
            "status": "fail",
            "passed": passed,
            "total": total,
            "failures": failures,
            "detail": f"candidate fails {len(failures)}/{total} test cases",
        }
    return {
        "status": "pass",
        "passed": passed,
        "total": total,
        "failures": [],
        "detail": f"passed {passed}/{total} I/O test cases (tested, not proven)",
    }
