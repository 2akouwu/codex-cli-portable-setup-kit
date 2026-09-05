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
  ``REVERIFY_ALLOW_NATIVE_EXEC=1``. When enabled, both the compile and the run go
  through :mod:`reverify.sandbox` (wall-clock timeout, CPU / memory / file-size /
  process-count limits, output cap, scrubbed env, isolated cwd), so a runaway or
  fork-bombing candidate is contained. It is still not a boundary against a
  determined attacker — for hostile corpora run it inside a container as well.
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

try:  # package import
    from .sandbox import run_sandboxed, SandboxLimits
    from .behavior import gen_inputs
except ImportError:  # flat import (CLI / tests)
    from sandbox import run_sandboxed, SandboxLimits
    from behavior import gen_inputs

_MB = 1024 * 1024
# Compilation runs a (trusted) compiler over untrusted source: cap time / memory
# so a macro/template bomb cannot hang or OOM the host, but leave the process
# count unlimited — the compiler forks cc1 / as / ld.
_COMPILE_LIMITS = SandboxLimits(cpu_seconds=None, memory_bytes=1536 * _MB,
                                file_size_bytes=64 * _MB, max_processes=None, output_bytes=_MB)
# The candidate binary is fully untrusted: tight CPU / memory, small output, and
# a process-count limit to blunt fork bombs.
_RUN_LIMITS = SandboxLimits(cpu_seconds=5, memory_bytes=256 * _MB,
                            file_size_bytes=8 * _MB, max_processes=32, output_bytes=256 * 1024)

NATIVE_EXEC_ENV = "REVERIFY_ALLOW_NATIVE_EXEC"
NATIVE_EXEC_HINT = (
    f"native execution of candidate C is off by default; set {NATIVE_EXEC_ENV}=1 to enable it "
    "(compile and run are then confined by reverify.sandbox; for hostile corpora also use a container)"
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
    limits = SandboxLimits(wall_seconds=timeout, cpu_seconds=_COMPILE_LIMITS.cpu_seconds,
                           memory_bytes=_COMPILE_LIMITS.memory_bytes, file_size_bytes=_COMPILE_LIMITS.file_size_bytes,
                           max_processes=_COMPILE_LIMITS.max_processes, output_bytes=_COMPILE_LIMITS.output_bytes)
    res = run_sandboxed(cmd, cwd=workdir, limits=limits)
    if res.timed_out:
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
    """Run ``binary`` with ``input_args`` as argv (sandboxed); parse one int from stdout."""
    limits = SandboxLimits(wall_seconds=timeout, cpu_seconds=min(int(timeout) or 1, _RUN_LIMITS.cpu_seconds),
                           memory_bytes=_RUN_LIMITS.memory_bytes, file_size_bytes=_RUN_LIMITS.file_size_bytes,
                           max_processes=_RUN_LIMITS.max_processes, output_bytes=_RUN_LIMITS.output_bytes)
    res = run_sandboxed([binary, *[str(a) for a in input_args]],
                        cwd=os.path.dirname(binary) or None, limits=limits)
    if not res.ok:
        return None
    text = res.stdout.decode("utf-8", "ignore").strip()
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


def _compile_into(c_source: str, subdir: str, cc: str, timeout: int) -> Optional[str]:
    os.makedirs(subdir, exist_ok=True)
    return compile_candidate(c_source, cc=cc, timeout=timeout, workdir=subdir)


def functions_equiv_verify(
    candidate_c: str,
    *,
    reference_c: Optional[str] = None,
    record: Optional[Dict[str, Any]] = None,
    nargs: int = 2,
    inputs: Optional[Sequence[Sequence[int]]] = None,
    cc: str = "gcc",
    timeout: int = 30,
    max_inputs: int = 40,
) -> Dict[str, Any]:
    """Do two implementations compute the same thing? Compile both, run over shared inputs, compare.

    This is the everyday "did the rewrite / the AI's version preserve behaviour?" check, one
    level up from ``exebench_verify`` (which compares a candidate against *recorded* I/O): here
    the oracle is a **reference implementation**, and the I/O is generated by running it. Both
    programs use the argv-in / one-int-out contract of this module.

    Pass ``reference_c`` (the trusted implementation) or ``record`` (recorded I/O — then this is
    just ``exebench_verify``). Returns ``{status, passed, total, failures, detail}``: ``pass`` is
    *tested, not proven* (equal on every input tried); a single mismatch is a definite refutation
    with the failing input, the reference output and the candidate output as witness. Off unless
    ``REVERIFY_ALLOW_NATIVE_EXEC=1``; both compiles and both runs are sandboxed.
    """
    if reference_c is None and record is not None:
        return exebench_verify(record, candidate_c, cc=cc, timeout=timeout)
    if reference_c is None:
        return _inconclusive(0, "functions_equiv needs 'reference_c' (a reference implementation) or 'record'")
    if not native_exec_allowed():
        return _inconclusive(0, NATIVE_EXEC_HINT)
    if not has_compiler(cc):
        return _inconclusive(0, f"no C compiler '{cc}' available; cannot compile the implementations")

    cases = [tuple(int(x) for x in c) for c in inputs] if inputs else gen_inputs(nargs, 32)
    cases = cases[:max_inputs]
    total = len(cases)
    with tempfile.TemporaryDirectory(prefix="funceq.") as base:
        ref_bin = _compile_into(reference_c, os.path.join(base, "ref"), cc, timeout)
        if ref_bin is None:
            return _inconclusive(total, "reference implementation did not compile")
        cand_bin = _compile_into(candidate_c, os.path.join(base, "cand"), cc, timeout)
        if cand_bin is None:
            return _inconclusive(total, "candidate implementation did not compile")
        failures: List[Dict[str, Any]] = []
        passed = compared = 0
        for case in cases:
            expected = run_case(ref_bin, case, timeout=timeout)
            if expected is None:
                continue  # the reference itself failed / produced no int on this input: not comparable
            got = run_case(cand_bin, case, timeout=timeout)
            compared += 1
            if got == expected:
                passed += 1
            else:
                failures.append({"input": list(case), "reference": expected, "candidate": got})
    if compared == 0:
        return _inconclusive(total, "reference produced no comparable output on any input")
    if failures:
        return {
            "status": "fail",
            "passed": passed,
            "total": compared,
            "failures": failures,
            "detail": f"candidate differs from the reference on {len(failures)}/{compared} inputs",
        }
    return {
        "status": "pass",
        "passed": passed,
        "total": compared,
        "failures": [],
        "detail": f"candidate matches the reference on all {compared} inputs tested (tested, not proven)",
    }


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
