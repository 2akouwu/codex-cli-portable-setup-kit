#!/usr/bin/env python3
"""Tool-grounded claim verification — the core idea behind Reverify.

A *claim* is a hypothesis about a binary: "the bytes at 0x40 are `55 8B EC`",
"field 3 of this Protobuf message is the string 'admin'", "the routine at this
offset computes `eax = 6`". Language models are good at producing such claims
and bad at guaranteeing they are true. Reverify makes the **deterministic
toolkit the judge**: each claim is checked against the actual bytes with the
parsers, disassembler, emulator, pattern scanner, and protocol dissector, and is
only ever reported as ``VERIFIED`` when the binary itself backs it up.

Verdicts
--------
- ``VERIFIED``     — the bytes support the claim.
- ``REFUTED``      — the bytes contradict the claim.
- ``INCONCLUSIVE`` — the tools cannot decide (bad offset, malformed claim, a
                     format the relevant tool does not understand).
- ``OBSERVED``     — the claim asked the tools for a value instead of asserting
                     one (``observe: true`` or a missing ``expected``); the value
                     is reported but nothing is scored.
- ``INVALIDATED``  — the claim depended (``depends_on``) on a claim that was
                     refuted, so it cannot stand on its own.

Scoring (anti-gaming)
---------------------
"All claims verified" is easy to reach by asserting trivia — the file starts
with ``MZ``, ``.text`` exists — so a verified set is also **weighted by how much
it says**. Each result carries a ``weight``: zero for claims derivable from the
fact sheet the model was shown, for self-referential claims (inline code/data
that does not occur in the binary), for duplicates, and for echoes of the tool's
own previous output; otherwise a surprisal tier by claim kind and specificity.
The report exposes ``information`` (sum of weights of verified claims) and
``grounded`` = trustworthy **and** informative. This follows the CORE
refinement of FActScore (Jiang et al., 2024): credit only claims that are
factual, informative and non-repetitive.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

try:  # package import (e.g. ``from reverify import Verifier``)
    from .disasm import Disassembler, pattern_scan
    from .emulator import make_emulator
    from .protocol_parser import ProtobufDissector
    from .binary import parse_binary, shannon_entropy
except ImportError:  # flat import (CLI, MCP server, and the test suite)
    from disasm import Disassembler, pattern_scan
    from emulator import make_emulator
    from protocol_parser import ProtobufDissector
    from binary import parse_binary, shannon_entropy

VERIFIED = "VERIFIED"
REFUTED = "REFUTED"
INCONCLUSIVE = "INCONCLUSIVE"
OBSERVED = "OBSERVED"
INVALIDATED = "INVALIDATED"

_META_KEYS = ("kind", "note", "id", "depends_on", "observe")


class ClaimError(Exception):
    """Raised when a claim is structurally malformed (missing required keys)."""


@dataclass
class Claim:
    """A single hypothesis to be checked against the binary.

    Attributes:
        kind: one of the supported claim kinds (see ``Verifier.SUPPORTED``).
        params: kind-specific parameters. Offsets may carry ``space`` =
            ``"file"`` (default), ``"rva"`` or ``"va"``; the verifier translates
            through the section table and echoes all three in the evidence.
        note: free-text rationale. Never verified; rendered separately.
        id: optional identifier so other claims can ``depends_on`` it.
        depends_on: ids of claims this one rests on; a refuted dependency
            invalidates this claim.
        observe: ask the tools for the value instead of asserting one.
    """

    kind: str
    params: Dict[str, Any] = field(default_factory=dict)
    note: str = ""
    id: Optional[str] = None
    depends_on: List[str] = field(default_factory=list)
    observe: bool = False

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Claim":
        if not isinstance(data, dict) or "kind" not in data:
            raise ClaimError("claim must be an object with a 'kind' field")
        params = data.get("params")
        if params is None:
            # Allow a flat form: everything except the meta keys is a parameter.
            params = {k: v for k, v in data.items() if k not in _META_KEYS}
        deps = data.get("depends_on") or []
        if isinstance(deps, str):
            deps = [deps]
        return cls(
            kind=str(data["kind"]),
            params=dict(params),
            note=str(data.get("note", "")),
            id=str(data["id"]) if data.get("id") is not None else None,
            depends_on=[str(d) for d in deps],
            observe=bool(data.get("observe", False)),
        )


def _clean_hex(text: str) -> bytes:
    cleaned = "".join(str(text).split()).replace("0x", "").replace("0X", "")
    return bytes.fromhex(cleaned)


def _as_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    return int(str(value), 0)


def _norm_ops(s: str) -> str:
    return "".join(str(s).lower().split())


def _entropy_norm(buf: bytes) -> float:
    """Entropy of ``buf`` relative to the maximum possible for its length (0..1)."""
    n = len(buf)
    if n <= 1:
        return 1.0
    max_h = min(8.0, math.log2(n))
    return shannon_entropy(buf) / max_h if max_h > 0 else 1.0


def _occurrences(data: bytes, needle: bytes) -> int:
    if not needle:
        return 0
    count, start = 0, 0
    while True:
        idx = data.find(needle, start)
        if idx == -1:
            return count
        count += 1
        start = idx + 1


class Verifier:
    """Checks claims about one binary against the deterministic toolkit."""

    SUPPORTED = (
        "bytes_at",
        "u16_at",
        "u32_at",
        "u64_at",
        "pattern_present",
        "string_present",
        "instructions",
        "emulate_result",
        "protobuf_field",
        "import_present",
        "export_present",
        "section_present",
        "pe_import",  # alias of import_present
    )

    def __init__(self, data: bytes):
        self.data = data
        self._bin_cache = None

    def _binary(self):
        """Parsed view of the binary (lief when available), cached per verifier."""
        if self._bin_cache is None:
            self._bin_cache = parse_binary(self.data)
        return self._bin_cache

    # -- dispatch -----------------------------------------------------------

    def verify(self, claim: Claim) -> Dict[str, Any]:
        """Check a single claim and return a structured verdict."""
        handler = getattr(self, f"_check_{claim.kind}", None)
        if handler is None:
            return self._result(claim, INCONCLUSIVE, {}, f"unknown claim kind '{claim.kind}'")
        params = dict(claim.params)
        if claim.observe:
            params["observe"] = True
        try:
            verdict, evidence, detail = handler(params)
        except ClaimError as exc:
            return self._result(claim, INCONCLUSIVE, {}, f"malformed claim: {exc}")
        except Exception as exc:  # pragma: no cover - defensive
            return self._result(claim, INCONCLUSIVE, {}, f"tool error: {exc}")
        return self._result(claim, verdict, evidence, detail)

    def verify_all(
        self,
        claims: List[Claim],
        facts: Optional[Dict[str, Any]] = None,
        min_information: float = 1.0,
    ) -> Dict[str, Any]:
        """Check many claims, apply dependencies, and score how much they say.

        ``facts`` is the fact sheet the model was shown; claims derivable from
        it get zero weight. ``min_information`` is the weight sum a verified set
        must reach to count as informative.
        """
        results = [self.verify(c) for c in claims]
        _apply_dependencies(results)
        return summarize(results, facts=facts, min_information=min_information)

    # -- addressing -----------------------------------------------------------

    def _resolve_offset(self, p: Dict[str, Any]) -> Tuple[Optional[int], Dict[str, Any]]:
        """Turn ``offset`` (+ optional ``space``) into a file offset with evidence."""
        space = str(p.get("space", "file")).lower()
        given = _as_int(p["offset"])
        info: Dict[str, Any] = {"space": space, "given": hex(given)}
        b = self._binary()
        parseable = b.format != "raw" and not b.error
        if space == "file":
            off = given
            if parseable:
                rva = b.offset_to_rva(off)
                if rva is not None:
                    info["rva"] = hex(rva)
                    if b.image_base is not None:
                        info["va"] = hex(b.image_base + rva)
        elif space in ("rva", "va"):
            if not parseable:
                return None, {**info, "error": "address translation needs a parseable binary"}
            if space == "va":
                if b.image_base is None:
                    return None, {**info, "error": "binary has no image base for VA translation"}
                rva = given - b.image_base
            else:
                rva = given
            off = b.rva_to_offset(rva)
            if off is None:
                return None, {**info, "error": "address is not inside any section"}
            info["rva"] = hex(rva)
            if b.image_base is not None:
                info["va"] = hex(b.image_base + rva)
        else:
            return None, {**info, "error": f"unknown address space '{space}' (use file|rva|va)"}
        info["file_offset"] = hex(off)
        return off, info

    # -- claim handlers -----------------------------------------------------
    # Each returns (verdict, evidence_dict, detail_str).

    def _check_bytes_at(self, p: Dict[str, Any]):
        """Claim: the bytes at ``offset`` equal ``expected`` (hex). ``observe`` reads them."""
        if "offset" not in p:
            raise ClaimError("bytes_at requires 'offset'")
        observe = bool(p.get("observe")) or "expected" not in p
        length = _as_int(p["length"]) if "length" in p else None
        expected = None if observe else _clean_hex(p["expected"])
        off, addr = self._resolve_offset(p)
        if off is None:
            return INCONCLUSIVE, {"address": addr, "file_size": len(self.data)}, addr.get("error", "bad address")
        n = length if length is not None else (len(expected) if expected is not None else 4)
        if off < 0 or off + n > len(self.data):
            return INCONCLUSIVE, {"address": addr, "file_size": len(self.data)}, "offset out of range"
        actual = self.data[off : off + n]
        evidence: Dict[str, Any] = {"address": addr, "actual": actual.hex()}
        if observe:
            return OBSERVED, evidence, "bytes read"
        evidence["expected"] = expected.hex()
        evidence["weight_basis"] = self._bytes_basis(expected)
        if actual == expected:
            return VERIFIED, evidence, "bytes match"
        evidence["nearest_offset_of_expected"] = self._nearest(expected, off)
        return REFUTED, evidence, "bytes differ"

    def _check_int_at(self, p: Dict[str, Any], size: int, kind: str):
        if "offset" not in p:
            raise ClaimError(f"{kind} requires 'offset'")
        observe = bool(p.get("observe")) or "expected" not in p
        endian = str(p.get("endian", "le")).lower()
        if endian not in ("le", "be"):
            raise ClaimError("endian must be 'le' or 'be'")
        off, addr = self._resolve_offset(p)
        if off is None:
            return INCONCLUSIVE, {"address": addr}, addr.get("error", "bad address")
        if off < 0 or off + size > len(self.data):
            return INCONCLUSIVE, {"address": addr, "file_size": len(self.data)}, "offset out of range"
        raw = self.data[off : off + size]
        actual = int.from_bytes(raw, "little" if endian == "le" else "big")
        evidence: Dict[str, Any] = {"address": addr, "raw": raw.hex(), "actual": hex(actual), "endian": endian}
        if observe:
            return OBSERVED, evidence, "value read"
        want = _as_int(p["expected"])
        evidence["expected"] = hex(want)
        want_bytes = want.to_bytes(size, "little" if endian == "le" else "big", signed=False) if 0 <= want < (1 << (8 * size)) else None
        if want_bytes:
            evidence["weight_basis"] = self._bytes_basis(want_bytes)
        if actual == want:
            return VERIFIED, evidence, "value matches"
        evidence["nearest_offset_of_expected"] = self._nearest(want_bytes, off) if want_bytes else None
        return REFUTED, evidence, "value differs"

    def _check_u16_at(self, p):
        return self._check_int_at(p, 2, "u16_at")

    def _check_u32_at(self, p):
        return self._check_int_at(p, 4, "u32_at")

    def _check_u64_at(self, p):
        return self._check_int_at(p, 8, "u64_at")

    def _bytes_basis(self, needle: bytes) -> Dict[str, Any]:
        """What the weight is measured from: how often the content occurs here, and its entropy."""
        return {
            "occurrences": _occurrences(self.data, needle),
            "length": len(needle),
            "entropy_norm": round(_entropy_norm(needle), 3),
        }

    def _nearest(self, needle: Optional[bytes], around: int, window: int = 256) -> Optional[str]:
        """Where the expected bytes actually sit, if anywhere within ±window."""
        if not needle:
            return None
        lo, hi = max(0, around - window), min(len(self.data), around + window + len(needle))
        idx = self.data.find(needle, lo, hi)
        return hex(idx) if idx != -1 else None

    def _check_pattern_present(self, p: Dict[str, Any]):
        """Claim: AOB ``pattern`` occurs (optionally at ``offset`` / ``count`` times)."""
        if "pattern" not in p:
            raise ClaimError("pattern_present requires 'pattern'")
        matches = pattern_scan(self.data, str(p["pattern"]))
        fixed = [t for t in str(p["pattern"]).split() if t not in ("?", "??")]
        evidence: Dict[str, Any] = {
            "match_offsets": [hex(m) for m in matches[:64]],
            "match_count": len(matches),
            "weight_basis": {"occurrences": len(matches), "length": len(fixed), "entropy_norm": 1.0},
        }
        if "offset" in p:
            want, addr = self._resolve_offset(p)
            evidence["address"] = addr
            if want is None:
                return INCONCLUSIVE, evidence, addr.get("error", "bad address")
            ok = want in matches
            return (VERIFIED if ok else REFUTED), evidence, (
                "pattern present at claimed offset" if ok else "pattern not at claimed offset"
            )
        if "count" in p:
            want = _as_int(p["count"])
            ok = len(matches) == want
            return (VERIFIED if ok else REFUTED), evidence, f"expected {want} matches, found {len(matches)}"
        if matches:
            return VERIFIED, evidence, "pattern present"
        return REFUTED, evidence, "pattern absent"

    def _check_string_present(self, p: Dict[str, Any]):
        """Claim: ``value`` appears as raw bytes (optionally at ``offset``)."""
        if "value" not in p:
            raise ClaimError("string_present requires 'value'")
        encoding = str(p.get("encoding", "utf-8"))
        try:
            needle = str(p["value"]).encode(encoding)
        except LookupError:
            raise ClaimError(f"unknown encoding '{encoding}'")
        all_offsets = []
        start = 0
        while True:
            idx = self.data.find(needle, start)
            if idx == -1:
                break
            all_offsets.append(idx)
            start = idx + 1
        evidence: Dict[str, Any] = {
            "found_offsets": [hex(o) for o in all_offsets[:64]],
            "occurrences": len(all_offsets),
            "weight_basis": self._bytes_basis(needle),
        }
        if "offset" in p:
            want, addr = self._resolve_offset(p)
            evidence["address"] = addr
            if want is None:
                return INCONCLUSIVE, evidence, addr.get("error", "bad address")
            ok = want in all_offsets
            return (VERIFIED if ok else REFUTED), evidence, (
                "string present at claimed offset" if ok else "string not at claimed offset"
            )
        if all_offsets:
            return VERIFIED, evidence, "string present"
        return REFUTED, evidence, "string absent"

    def _check_instructions(self, p: Dict[str, Any]):
        """Claim: disassembling ``length`` bytes at ``offset`` yields ``mnemonics``.

        ``mode='contains'`` accepts an ordered subsequence; the default
        ``mode='exact'`` requires the full sequence. Optional ``operands`` (one
        string per instruction, or null to skip) are compared too.
        """
        if "offset" not in p or "mnemonics" not in p:
            raise ClaimError("instructions requires 'offset' and 'mnemonics'")
        expected = [str(m).lower() for m in p["mnemonics"]]
        arch = str(p.get("arch", "x86_64"))
        mode = str(p.get("mode", "exact"))
        length = _as_int(p["length"]) if "length" in p else None
        off, addr = self._resolve_offset(p)
        if off is None:
            return INCONCLUSIVE, {"address": addr}, addr.get("error", "bad address")
        if off < 0 or off >= len(self.data):
            return INCONCLUSIVE, {"address": addr, "file_size": len(self.data)}, "offset out of range"
        code = self.data[off : off + length] if length else self.data[off : off + 64]
        base = _as_int(p["base"]) if "base" in p else 0x1000
        insns = Disassembler(arch=arch).disassemble(code, base_address=base)
        actual = [i.mnemonic.lower() for i in insns]
        actual_ops = [i.op_str for i in insns]
        matched = b"".join(bytes(i.bytes) for i in insns[: len(expected)])
        evidence: Dict[str, Any] = {
            "address": addr,
            "actual_mnemonics": actual[: max(len(expected) + 4, 8)],
            "actual_operands": actual_ops[: max(len(expected) + 4, 8)],
            "expected_mnemonics": expected,
            "weight_basis": self._bytes_basis(matched) if matched else None,
        }
        if mode == "contains":
            ok = _is_subsequence(expected, actual)
        else:
            ok = actual[: len(expected)] == expected if length is None else actual == expected
        if ok and p.get("operands"):
            wants = list(p["operands"])
            for i, w in enumerate(wants):
                if w is None:
                    continue
                if i >= len(actual_ops) or _norm_ops(actual_ops[i]) != _norm_ops(w):
                    ok = False
                    evidence["operand_mismatch_index"] = i
                    break
        return (VERIFIED if ok else REFUTED), evidence, f"mode={mode}"

    def _check_emulate_result(self, p: Dict[str, Any]):
        """Claim: emulating the code leaves registers at ``expect_registers``.

        Code comes from ``offset``/``length`` into the binary (preferred) or an
        inline ``code`` hex string. Inline code that does not occur in the binary
        is flagged ``self_referential`` and carries no weight. ``observe`` (or a
        missing ``expect_registers``) reports the register state instead.
        """
        arch = str(p.get("arch", "x86_64"))
        base = _as_int(p["base"]) if "base" in p else 0x1000
        max_steps = _as_int(p["max_steps"]) if "max_steps" in p else 1000
        observe = bool(p.get("observe")) or "expect_registers" not in p
        evidence: Dict[str, Any] = {}
        if "offset" in p:
            off, addr = self._resolve_offset(p)
            evidence["address"] = addr
            if off is None:
                return INCONCLUSIVE, evidence, addr.get("error", "bad address")
            length = _as_int(p["length"]) if "length" in p else 64
            if off < 0 or off >= len(self.data):
                return INCONCLUSIVE, {**evidence, "file_size": len(self.data)}, "offset out of range"
            code = self.data[off : off + length]
        elif "code" in p:
            code = _clean_hex(p["code"])
            evidence["self_referential"] = self.data.find(code) == -1 if code else True
        else:
            raise ClaimError("emulate_result requires 'offset' or 'code'")

        emu = make_emulator(arch=arch, prefer=str(p.get("backend", "auto")))
        emu.load_code(code, base_address=base)
        state = emu.run(max_steps=max_steps)
        evidence["steps_executed"] = emu.steps_executed
        evidence["backend"] = state.get("backend", "pure-python")
        evidence["weight_basis"] = {
            "steps": emu.steps_executed,
            "entropy_norm": round(_entropy_norm(code), 3),
            "inline": "code" in p,
        }
        if observe:
            evidence["registers"] = state.get("registers", {})
            return OBSERVED, evidence, "emulated; register state reported"

        expect = {str(k).lower(): _as_int(v) for k, v in dict(p["expect_registers"]).items()}
        observed = {name: emu.reg_read(name) for name in expect}
        mismatches = {
            name: {"expected": hex(want), "actual": hex(observed[name])}
            for name, want in expect.items()
            if observed[name] != want
        }
        evidence.update({
            "expect_registers": {k: hex(v) for k, v in expect.items()},
            "observed_registers": {k: hex(v) for k, v in observed.items()},
            "mismatches": mismatches,
        })
        if not mismatches:
            return VERIFIED, evidence, "register state matches"
        return REFUTED, evidence, f"{len(mismatches)} register(s) mismatched"

    def _check_protobuf_field(self, p: Dict[str, Any]):
        """Claim: Protobuf ``field`` has wire ``type`` and optionally ``value``."""
        if "field" not in p:
            raise ClaimError("protobuf_field requires 'field'")
        field_no = _as_int(p["field"])
        evidence: Dict[str, Any] = {}
        if "data" in p:
            source = _clean_hex(p["data"])
            evidence["self_referential"] = self.data.find(source) == -1 if source else True
        elif "offset" in p:
            off, addr = self._resolve_offset(p)
            evidence["address"] = addr
            if off is None:
                return INCONCLUSIVE, evidence, addr.get("error", "bad address")
            length = _as_int(p["length"]) if "length" in p else 512
            source = self.data[off : off + length]
        else:
            source = self.data
        tree = ProtobufDissector.dissect(source)
        key = f"field_{field_no}"
        if key not in tree:
            evidence["present_fields"] = list(tree.keys())
            return REFUTED, evidence, "field not present"
        entries = tree[key]
        evidence.update({"field": key, "entries": entries})
        want_type = str(p["type"]).lower() if "type" in p else None
        if want_type is not None:
            types = {e.get("type") for e in entries}
            if want_type not in types:
                return REFUTED, evidence, f"types present: {sorted(t for t in types if t)}"
        if "value" in p:
            want = p["value"]
            if not any(_value_matches(e, want) for e in entries):
                return REFUTED, evidence, "no entry matches claimed value"
        return VERIFIED, evidence, "field matches"

    def _not_parseable(self, info):
        if info.format == "raw" or info.error:
            return INCONCLUSIVE, {"format": info.format, "error": info.error}, "not a parseable binary"
        return None

    def _check_import_present(self, p: Dict[str, Any]):
        """Claim: the binary imports ``function`` (optionally from ``lib``/``dll``). PE, ELF, Mach-O."""
        lib = p.get("lib", p.get("dll"))
        if "function" not in p and lib is None:
            raise ClaimError("import_present requires 'function' and/or 'lib'")
        info = self._binary()
        bad = self._not_parseable(info)
        if bad:
            return bad
        evidence = {
            "format": info.format,
            "backend": info.backend,
            "imported_libs": list(info.imports.keys()),
            "libraries": info.libraries,
        }
        func = str(p["function"]) if "function" in p else None
        lib_s = str(lib).lower() if lib is not None else None
        lib_known = lib_s is not None and (
            any(l.lower() == lib_s for l in info.imports) or any(l.lower() == lib_s for l in info.libraries)
        )
        if func is None:
            return (VERIFIED if lib_known else REFUTED), evidence, "library import check"
        if lib_s is not None and info.format == "PE":
            ok = info.has_import(func, lib=lib_s)
        else:
            ok = info.has_import(func) and (lib_s is None or lib_known)
        return (VERIFIED if ok else REFUTED), evidence, ("import present" if ok else "import absent")

    def _check_pe_import(self, p: Dict[str, Any]):
        """Backward-compatible alias of ``import_present``."""
        return self._check_import_present(p)

    def _check_export_present(self, p: Dict[str, Any]):
        """Claim: the binary exports symbol ``name``."""
        if "name" not in p:
            raise ClaimError("export_present requires 'name'")
        info = self._binary()
        bad = self._not_parseable(info)
        if bad:
            return bad
        ok = info.has_export(str(p["name"]))
        evidence = {"format": info.format, "backend": info.backend, "export_count": len(info.exports), "exports_sample": info.exports[:32]}
        return (VERIFIED if ok else REFUTED), evidence, ("export present" if ok else "export absent")

    def _check_section_present(self, p: Dict[str, Any]):
        """Claim: a section named ``name`` exists (optionally with ``virtual_address``)."""
        if "name" not in p:
            raise ClaimError("section_present requires 'name'")
        info = self._binary()
        bad = self._not_parseable(info)
        if bad:
            return bad
        sec = info.section(str(p["name"]))
        evidence = {"format": info.format, "backend": info.backend, "sections": [s.name for s in info.sections]}
        if sec is None:
            return REFUTED, evidence, "section absent"
        evidence["section"] = {
            "virtual_address": hex(sec.virtual_address),
            "virtual_size": sec.virtual_size,
            "raw_size": sec.raw_size,
            "offset": sec.offset,
        }
        if "virtual_address" in p and _as_int(p["virtual_address"]) != sec.virtual_address:
            return REFUTED, evidence, "section present but virtual address differs"
        return VERIFIED, evidence, "section present"

    # -- helpers ------------------------------------------------------------

    def _result(self, claim: Claim, verdict: str, evidence: Dict[str, Any], detail: str) -> Dict[str, Any]:
        return {
            "id": claim.id,
            "kind": claim.kind,
            "note": claim.note,
            "depends_on": list(claim.depends_on),
            "verdict": verdict,
            "detail": detail,
            "evidence": evidence,
            "params": claim.params,
        }


# ---------------------------------------------------------------------------
# Dependencies, weighting and summary (module-level so the agent can rescore)
# ---------------------------------------------------------------------------

def _apply_dependencies(results: List[Dict[str, Any]]) -> None:
    """A claim whose dependency was refuted/invalidated cannot stand; mark it."""
    verdicts = {r["id"]: r["verdict"] for r in results if r.get("id")}
    for _ in range(2):  # two passes settle short chains
        for r in results:
            if r["verdict"] in (INVALIDATED,):
                continue
            bad = [d for d in r.get("depends_on", []) if verdicts.get(d) in (REFUTED, INVALIDATED)]
            if bad:
                r["verdict_before_invalidation"] = r["verdict"]
                r["verdict"] = INVALIDATED
                r["detail"] = f"depends on refuted claim(s): {', '.join(bad)}"
                if r.get("id"):
                    verdicts[r["id"]] = INVALIDATED


def claim_key(kind: str, params: Dict[str, Any]) -> str:
    """Stable identity of a claim for de-duplication."""
    clean = {k: v for k, v in params.items() if k != "observe"}
    return f"{kind}:{json.dumps(clean, sort_keys=True, default=str)}"


def derivable_from_facts(result: Dict[str, Any], facts: Optional[Dict[str, Any]]) -> bool:
    """True when the claim restates something the model was already shown."""
    if not facts:
        return False
    kind, p = result["kind"], result.get("params", {})
    first_hex = str(facts.get("first_32_bytes_hex", "") or "")
    shown_bytes = len(first_hex) // 2
    if kind in ("bytes_at", "u16_at", "u32_at", "u64_at"):
        if str(p.get("space", "file")).lower() != "file":
            return False
        try:
            off = _as_int(p.get("offset", 0))
        except (ValueError, TypeError):
            return False
        size = {"u16_at": 2, "u32_at": 4, "u64_at": 8}.get(kind)
        if size is None:
            size = len(_clean_hex(p["expected"])) if p.get("expected") else 0
        if off >= 0 and off + size <= shown_bytes:
            return True
        obs = (facts.get("observed") or {}).get(f"{kind}@{hex(off)}")
        if obs is not None and "expected" in p:
            want = p["expected"]
            try:
                if kind == "bytes_at":
                    return _clean_hex(want).hex() == str(obs).lower()
                return _as_int(want) == _as_int(obs)
            except (ValueError, TypeError):
                return False
        return False
    binary = facts.get("binary") or {}
    if kind == "string_present":
        return str(p.get("value")) in (facts.get("top_strings") or [])
    if kind == "section_present":
        return str(p.get("name")) in (binary.get("sections") or [])
    if kind in ("import_present", "pe_import"):
        imps = facts.get("imports") or {}
        fn = p.get("function")
        lib = p.get("lib", p.get("dll"))
        if fn and any(fn in (v or []) for v in imps.values()):
            return True
        if fn is None and lib and any(str(lib).lower() == str(k).lower() for k in imps):
            return True
        return False
    if kind == "export_present":
        return str(p.get("name")) in (facts.get("exports") or [])
    if kind == "pattern_present" and "offset" not in p and "count" not in p:
        pat = str(p.get("pattern", "")).replace(" ", "").lower()
        return bool(pat) and "?" not in pat and pat in first_hex.lower()
    return False


def base_weight(result: Dict[str, Any]) -> float:
    """How much a claim says (0..1), measured from the binary itself where possible.

    For content claims the weight is driven by ``evidence.weight_basis``: how
    often the expected content occurs in this binary (rarity) and how much
    entropy it has. Zero padding, ubiquitous prologues and patterns that match
    hundreds of places therefore weigh almost nothing even though they verify.
    For emulation the claim must actually execute (steps) over non-degenerate
    code (entropy). Structural kinds (imports/exports/sections/protobuf) keep a
    fixed tier until corpus base rates exist.
    """
    kind, p, ev = result["kind"], result.get("params", {}), result.get("evidence", {}) or {}
    if ev.get("self_referential"):
        return 0.0
    basis = ev.get("weight_basis") or {}
    occ = max(1, int(basis.get("occurrences", 1) or 1))
    rarity = (1.0 / occ) ** 0.5
    ent = max(0.0, float(basis.get("entropy_norm", 1.0))) ** 0.5

    if kind in ("bytes_at", "u16_at", "u32_at", "u64_at"):
        n = int(basis.get("length") or 0)
        if n == 0:
            try:
                n = len(_clean_hex(p["expected"])) if p.get("expected") else {"u16_at": 2, "u32_at": 4, "u64_at": 8}.get(kind, 0)
            except ValueError:
                n = 0
        return min(1.0, 0.3 + 0.1 * n) * rarity * ent
    if kind == "instructions":
        w = 0.8 if str(p.get("mode", "exact")) == "exact" else 0.4
        w = min(1.0, w + (0.1 if p.get("operands") else 0.0))
        return w * rarity
    if kind == "emulate_result":
        base = 1.0 if "offset" in p else 0.5
        steps = int(basis.get("steps", 0) or 0)
        return base * min(1.0, steps / 2.0) * ent
    if kind == "pattern_present":
        return (0.7 if ("offset" in p or "count" in p) else 0.4) * rarity
    if kind == "string_present":
        return (0.6 if "offset" in p else 0.4) * rarity
    # structural kinds: fixed tier until corpus base rates exist
    if kind == "protobuf_field":
        return 0.6 if "value" in p else 0.3
    if kind in ("import_present", "pe_import", "export_present"):
        return 0.3
    if kind == "section_present":
        return 0.3 if "virtual_address" in p else 0.2
    return 0.3


def summarize(
    results: List[Dict[str, Any]],
    facts: Optional[Dict[str, Any]] = None,
    min_information: float = 1.0,
) -> Dict[str, Any]:
    """Weight results (CORE-style) and build the report.

    Sets ``weight``, ``trivial``, ``duplicate`` on each result in place; the
    agent may set ``echoed`` beforehand to zero a claim that merely copied the
    tools' previous output.
    """
    seen = set()
    for r in results:
        key = claim_key(r["kind"], r.get("params", {}))
        r["duplicate"] = key in seen
        seen.add(key)
        r["trivial"] = derivable_from_facts(r, facts)
        if r["verdict"] in (OBSERVED, INVALIDATED) or r["duplicate"] or r["trivial"] or r.get("echoed"):
            r["weight"] = 0.0
        else:
            r["weight"] = round(base_weight(r), 3)

    counts = {VERIFIED: 0, REFUTED: 0, INCONCLUSIVE: 0, OBSERVED: 0, INVALIDATED: 0}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    scored = [r for r in results if r["verdict"] in (VERIFIED, REFUTED, INCONCLUSIVE)]
    information = round(sum(r["weight"] for r in results if r["verdict"] == VERIFIED), 3)
    weighted_total = round(sum(base_weight(r) for r in scored if not (r["duplicate"] or r["trivial"] or r.get("echoed"))), 3)
    trivial_verified = sum(1 for r in results if r["verdict"] == VERIFIED and r["weight"] == 0.0)
    total = len(results)
    trustworthy = counts[REFUTED] == 0 and counts[INCONCLUSIVE] == 0 and counts[INVALIDATED] == 0 and counts[VERIFIED] > 0
    informative = information >= float(min_information)
    return {
        "total_claims": total,
        "verified": counts[VERIFIED],
        "refuted": counts[REFUTED],
        "inconclusive": counts[INCONCLUSIVE],
        "observed": counts[OBSERVED],
        "invalidated": counts[INVALIDATED],
        "grounded_ratio": round(counts[VERIFIED] / len(scored), 4) if scored else 0.0,
        "information": information,
        "grounded_score": round(information / weighted_total, 4) if weighted_total else 0.0,
        "trivial_verified": trivial_verified,
        "duplicates": sum(1 for r in results if r["duplicate"]),
        "echoed": sum(1 for r in results if r.get("echoed")),
        "min_information": float(min_information),
        "trustworthy": trustworthy,
        "informative": informative,
        "grounded": trustworthy and informative,
        "results": results,
    }


def _is_subsequence(needle: List[str], haystack: List[str]) -> bool:
    it = iter(haystack)
    return all(any(x == n for x in it) for n in needle)


def _value_matches(entry: Dict[str, Any], want: Any) -> bool:
    if "value" not in entry:
        return False
    ev = entry["value"]
    if isinstance(want, str) and isinstance(ev, str):
        return ev == want
    try:
        return _as_int(ev) == _as_int(want)
    except (ValueError, TypeError):
        return str(ev) == str(want)


def verify_claims(
    data: bytes,
    claims: List[Dict[str, Any]],
    facts: Optional[Dict[str, Any]] = None,
    min_information: float = 1.0,
) -> Dict[str, Any]:
    """Convenience: verify a list of plain-dict claims against ``data``."""
    verifier = Verifier(data)
    parsed = [Claim.from_dict(c) for c in claims]
    return verifier.verify_all(parsed, facts=facts, min_information=min_information)
