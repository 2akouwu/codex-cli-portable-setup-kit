#!/usr/bin/env python3
"""Behavioral equivalence: verify a reconstruction by running it, not reading it.

The strongest form of "tool as judge". Instead of checking that a reconstructed
routine *looks* right, run the original function and the candidate over the same
inputs and compare the outputs. The candidate lives or dies empirically; a
mismatch hands back a concrete counterexample input — exactly what a reverse
engineer produces ("it differs at x = 0x1234"). This is the methodology behind
executable decompilation benchmarks (ExeBench I/O pairs; LLM4Decompile's
re-executability): correctness is measured by execution, not by appearance.

Honest scope and labelling:
- Testing over inputs shows behavioral agreement on those inputs; it is NOT a
  proof of equivalence (a function can differ only on one special value). Results
  say "equivalent over N inputs (tested, not proven)". A mismatch, by contrast,
  is a definite refutation with a witness.
- The original must be a self-contained computational function (no external
  calls, no unmodelled memory). Functions that fault or call out return
  INCONCLUSIVE rather than a false verdict.
- Needs Unicorn for real execution; without it, INCONCLUSIVE.
"""

from __future__ import annotations

import ast
import operator
from typing import Any, Dict, List, Optional, Sequence, Tuple

try:
    from .backends import HAS_UNICORN, HAS_Z3
except ImportError:
    from backends import HAS_UNICORN, HAS_Z3

# --- safe arithmetic expression evaluator (candidate as an expression) --------

_BINOPS = {
    ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
    ast.BitXor: operator.xor, ast.BitAnd: operator.and_, ast.BitOr: operator.or_,
    ast.LShift: operator.lshift, ast.RShift: operator.rshift,
    ast.Mod: operator.mod, ast.FloorDiv: operator.floordiv,
}
_UNARYOPS = {ast.Invert: operator.invert, ast.USub: operator.neg, ast.UAdd: operator.pos}


class ExprError(Exception):
    pass


def eval_expr(expr: str, variables: Dict[str, int]) -> int:
    """Evaluate a restricted integer expression. No calls/attributes/names but vars."""
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as exc:
        raise ExprError(f"bad expression: {exc}")

    def ev(node):
        if isinstance(node, ast.Expression):
            return ev(node.body)
        if isinstance(node, ast.BinOp) and type(node.op) in _BINOPS:
            r = ev(node.right)
            if type(node.op) in (ast.Mod, ast.FloorDiv) and r == 0:
                raise ZeroDivisionError
            if type(node.op) in (ast.LShift, ast.RShift) and not (0 <= ev(node.right) < 4096):
                return 0
            return _BINOPS[type(node.op)](ev(node.left), r)
        if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARYOPS:
            return _UNARYOPS[type(node.op)](ev(node.operand))
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        if isinstance(node, ast.Name):
            if node.id in variables:
                return variables[node.id]
            raise ExprError(f"unknown variable '{node.id}'")
        raise ExprError(f"disallowed expression element: {type(node).__name__}")

    return ev(tree)


# --- register-convention function runner (Unicorn) ----------------------------

_DEFAULT_ARG_REGS = {
    "x86_64": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],  # System V
    "x86_64_ms": ["rcx", "rdx", "r8", "r9"],             # Microsoft x64
}
_DEFAULT_RET = {"x86_64": "rax", "x86_64_ms": "rax"}
_BASE = 0x100000
_STACK = 0x400000
_EXIT = 0x1000


def run_function(
    code: bytes,
    args: Sequence[int],
    *,
    arch: str = "x86_64",
    arg_regs: Optional[List[str]] = None,
    ret_reg: Optional[str] = None,
    bits: int = 64,
    max_steps: int = 5000,
) -> Optional[int]:
    """Run ``code`` as a function with ``args`` in registers; return the result register.

    Returns the masked return value on a clean ``ret``, or ``None`` if the code
    faults, calls out, or never returns within ``max_steps``.
    """
    if not HAS_UNICORN:
        raise RuntimeError("unicorn required for behavioral execution")
    import unicorn
    from unicorn import x86_const

    key = "x86_64" if arch.lower() in ("x86_64", "x64", "amd64") else arch.lower()
    arg_regs = arg_regs or _DEFAULT_ARG_REGS.get(key, _DEFAULT_ARG_REGS["x86_64"])
    ret_reg = ret_reg or _DEFAULT_RET.get(key, "rax")
    mask = (1 << bits) - 1

    def reg(name):
        c = getattr(x86_const, f"UC_X86_REG_{name.upper()}", None)
        if c is None:
            raise RuntimeError(f"unknown register {name}")
        return c

    mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64 if bits == 64 else unicorn.UC_MODE_32)
    mu.mem_map(_BASE, 0x10000)
    mu.mem_map(_STACK, 0x20000)
    mu.mem_map(_EXIT, 0x1000)
    mu.mem_write(_BASE, bytes(code))
    sp = _STACK + 0x10000
    size = bits // 8
    sp -= size
    mu.mem_write(sp, _EXIT.to_bytes(size, "little"))  # return address sentinel
    mu.reg_write(reg("rsp" if bits == 64 else "esp"), sp)
    for i, a in enumerate(args):
        if i < len(arg_regs):
            mu.reg_write(reg(arg_regs[i]), a & mask)
    pc_reg = reg("rip" if bits == 64 else "eip")
    try:
        mu.emu_start(_BASE, _EXIT, count=max_steps)
    except unicorn.UcError:
        return None
    if mu.reg_read(pc_reg) != _EXIT:  # did not return cleanly (ran out / stuck)
        return None
    return mu.reg_read(reg(ret_reg)) & mask


# --- input generation ---------------------------------------------------------

def gen_inputs(nargs: int, bits: int, n: int = 24, seed: int = 0x5EED) -> List[Tuple[int, ...]]:
    """Boundary values plus deterministic pseudo-random tuples (no global RNG)."""
    mask = (1 << bits) - 1
    boundary = [0, 1, 2, mask, mask - 1, mask >> 1, 1 << (bits - 1), 0xFF, 0x100, 0x7FFFFFFF]
    out: List[Tuple[int, ...]] = []
    for b in boundary:
        out.append(tuple(b & mask for _ in range(nargs)))
    # a simple LCG so results are reproducible without Math.random-style globals
    state = seed
    for _ in range(n):
        tup = []
        for _ in range(nargs):
            state = (state * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
            tup.append(state & mask)
        out.append(tuple(tup))
    return out


# --- the comparison -----------------------------------------------------------

def behavioral_equiv(
    original_code: bytes,
    *,
    candidate_code: Optional[bytes] = None,
    expr: Optional[str] = None,
    nargs: int = 2,
    inputs: Optional[Sequence[Sequence[int]]] = None,
    arch: str = "x86_64",
    bits: int = 64,
    arg_regs: Optional[List[str]] = None,
    ret_reg: Optional[str] = None,
    max_inputs: int = 40,
) -> Dict[str, Any]:
    """Run original and candidate over the same inputs; compare outputs.

    Returns a dict: {status: 'equivalent'|'refuted'|'inconclusive', tested,
    counterexample?, detail}.
    """
    if not HAS_UNICORN:
        return {"status": "inconclusive", "detail": "unicorn not installed", "tested": 0}
    if candidate_code is None and expr is None:
        raise ValueError("need candidate_code or expr")

    mask = (1 << bits) - 1
    cases = [tuple(int(x) for x in c) for c in inputs] if inputs else gen_inputs(nargs, bits)
    cases = cases[:max_inputs]

    def eval_candidate(argv):
        if candidate_code is not None:
            return run_function(candidate_code, argv, arch=arch, arg_regs=arg_regs, ret_reg=ret_reg, bits=bits)
        variables = {f"x{i}": v for i, v in enumerate(argv)}
        variables["x"] = argv[0] if argv else 0
        try:
            return eval_expr(expr, variables) & mask
        except (ZeroDivisionError, ExprError):
            return None

    tested = 0
    for argv in cases:
        o = run_function(original_code, argv, arch=arch, arg_regs=arg_regs, ret_reg=ret_reg, bits=bits)
        if o is None:
            continue  # original could not run on this input; skip
        c = eval_candidate(argv)
        tested += 1
        if c is None or (o & mask) != (c & mask):
            return {
                "status": "refuted",
                "tested": tested,
                "counterexample": {
                    "input": [hex(a) for a in argv],
                    "original": hex(o & mask),
                    "candidate": (hex(c & mask) if c is not None else None),
                },
                "detail": "outputs differ on a concrete input",
            }
    if tested == 0:
        return {"status": "inconclusive", "detail": "original did not execute on any input", "tested": 0}
    return {
        "status": "equivalent",
        "tested": tested,
        "detail": f"behaviorally equivalent over {tested} inputs (tested, not proven)",
    }


# --- Z3 proof of expression equivalence (proof-grade, not sampled) ------------

_Z3_BINOPS = {
    ast.Add: lambda a, b: a + b, ast.Sub: lambda a, b: a - b, ast.Mult: lambda a, b: a * b,
    ast.BitXor: lambda a, b: a ^ b, ast.BitAnd: lambda a, b: a & b, ast.BitOr: lambda a, b: a | b,
    ast.LShift: lambda a, b: a << b,
}


def _expr_to_z3(expr: str, variables: Dict[str, Any]):
    """Compile a restricted integer expression into a Z3 bit-vector formula."""
    import z3
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as exc:
        raise ExprError(f"bad expression: {exc}")

    def ev(node):
        if isinstance(node, ast.Expression):
            return ev(node.body)
        if isinstance(node, ast.BinOp):
            t = type(node.op)
            if t in _Z3_BINOPS:
                return _Z3_BINOPS[t](ev(node.left), ev(node.right))
            if t is ast.RShift:
                return z3.LShR(ev(node.left), ev(node.right))  # logical (unsigned) shift
            raise ExprError(f"operator not supported in proofs: {t.__name__}")
        if isinstance(node, ast.UnaryOp):
            if isinstance(node.op, ast.Invert):
                return ~ev(node.operand)
            if isinstance(node.op, ast.USub):
                return -ev(node.operand)
            if isinstance(node.op, ast.UAdd):
                return ev(node.operand)
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            bits = variables["__bits__"]
            return z3.BitVecVal(node.value, bits)
        if isinstance(node, ast.Name):
            if node.id in variables:
                return variables[node.id]
            raise ExprError(f"unknown variable '{node.id}'")
        raise ExprError(f"disallowed expression element: {type(node).__name__}")

    return ev(tree)


def _count_vars(*exprs: str) -> int:
    import re
    n = -1
    for e in exprs:
        for m in re.findall(r"\bx(\d+)\b", e):
            n = max(n, int(m))
        if re.search(r"\bx\b", e):
            n = max(n, 0)
    return n + 1


def prove_expr_equiv(expr_a: str, expr_b: str, nvars: Optional[int] = None, bits: int = 64) -> Dict[str, Any]:
    """Prove two integer expressions equal for ALL inputs using Z3 (bit-vector logic).

    Returns {status: 'proven' | 'refuted' | 'inconclusive', counterexample?}. Unlike
    sampling, 'proven' means no input exists that distinguishes them.
    """
    if not HAS_Z3:
        return {"status": "inconclusive", "detail": "z3 not installed (pip install z3-solver)"}
    import z3
    if nvars is None:
        nvars = max(1, _count_vars(expr_a, expr_b))
    variables: Dict[str, Any] = {"__bits__": bits}
    for i in range(nvars):
        variables[f"x{i}"] = z3.BitVec(f"x{i}", bits)
    variables["x"] = variables["x0"]
    try:
        fa = _expr_to_z3(expr_a, variables)
        fb = _expr_to_z3(expr_b, variables)
    except ExprError as exc:
        return {"status": "inconclusive", "detail": str(exc)}

    solver = z3.Solver()
    solver.add(fa != fb)
    res = solver.check()
    if res == z3.unsat:
        return {"status": "proven", "detail": f"proven equivalent for all inputs (Z3, {bits}-bit)"}
    if res == z3.sat:
        m = solver.model()
        ce = {f"x{i}": hex(m[variables[f'x{i}']].as_long()) for i in range(nvars) if m[variables[f"x{i}"]] is not None}
        return {"status": "refuted", "counterexample": ce, "detail": "not equivalent (Z3 found a distinguishing input)"}
    return {"status": "inconclusive", "detail": "z3 returned unknown"}
