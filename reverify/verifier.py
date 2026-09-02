#!/usr/bin/env python3
"""Tool-grounded claim verification — the core idea behind Reverify.

A *claim* is a hypothesis about a binary: "the bytes at 0x40 are `55 8B EC`",
"field 3 of this Protobuf message is the string 'admin'", "the routine at this
offset computes `eax = 6`". Language models are good at producing such claims
and bad at guaranteeing they are true. Reverify makes the **deterministic
toolkit the judge**: each claim is checked against the actual bytes with the
PE parser, disassembler, emulator, pattern scanner, and protocol dissector, and
is only ever reported as ``VERIFIED`` when the binary itself backs it up.

This is the "model proposes, tools verify" loop. The model never gets to assert
a structural fact; it can only propose one, and the tools decide.

Verdicts
--------
- ``VERIFIED``     — the bytes support the claim.
- ``REFUTED``      — the bytes contradict the claim.
- ``INCONCLUSIVE`` — the tools cannot decide (bad offset, malformed claim, a
                     format the relevant tool does not understand).

Every result carries the *observed* evidence, so a refutation tells you what the
bytes actually were, not merely that the guess was wrong.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

try:  # package import (e.g. ``from reverify import Verifier``)
    from .disasm import Disassembler, pattern_scan
    from .emulator import make_emulator
    from .protocol_parser import ProtobufDissector
    from .binary import parse_binary
except ImportError:  # flat import (CLI, MCP server, and the test suite)
    from disasm import Disassembler, pattern_scan
    from emulator import make_emulator
    from protocol_parser import ProtobufDissector
    from binary import parse_binary

VERIFIED = "VERIFIED"
REFUTED = "REFUTED"
INCONCLUSIVE = "INCONCLUSIVE"


class ClaimError(Exception):
    """Raised when a claim is structurally malformed (missing required keys)."""


@dataclass
class Claim:
    """A single hypothesis to be checked against the binary.

    Attributes:
        kind: one of the supported claim kinds (see ``Verifier.SUPPORTED``).
        params: kind-specific parameters.
        note: free-text description carried through to the result, e.g. the
            model's natural-language rationale for the claim.
    """

    kind: str
    params: Dict[str, Any] = field(default_factory=dict)
    note: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Claim":
        if not isinstance(data, dict) or "kind" not in data:
            raise ClaimError("claim must be an object with a 'kind' field")
        params = data.get("params")
        if params is None:
            # Allow a flat form: everything except kind/note is a parameter.
            params = {k: v for k, v in data.items() if k not in ("kind", "note")}
        return cls(kind=str(data["kind"]), params=dict(params), note=str(data.get("note", "")))


def _clean_hex(text: str) -> bytes:
    cleaned = "".join(str(text).split()).replace("0x", "").replace("0X", "")
    return bytes.fromhex(cleaned)


def _as_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    return int(str(value), 0)


class Verifier:
    """Checks claims about one binary against the deterministic toolkit."""

    SUPPORTED = (
        "bytes_at",
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
            return self._result(
                claim, INCONCLUSIVE, {}, f"unknown claim kind '{claim.kind}'"
            )
        try:
            verdict, evidence, detail = handler(claim.params)
        except ClaimError as exc:
            return self._result(claim, INCONCLUSIVE, {}, f"malformed claim: {exc}")
        except Exception as exc:  # pragma: no cover - defensive
            return self._result(claim, INCONCLUSIVE, {}, f"tool error: {exc}")
        return self._result(claim, verdict, evidence, detail)

    def verify_all(self, claims: List[Claim]) -> Dict[str, Any]:
        """Check many claims and summarise how grounded the reconstruction is."""
        results = [self.verify(c) for c in claims]
        counts = {VERIFIED: 0, REFUTED: 0, INCONCLUSIVE: 0}
        for r in results:
            counts[r["verdict"]] += 1
        total = len(results)
        grounded = counts[VERIFIED]
        return {
            "total_claims": total,
            "verified": counts[VERIFIED],
            "refuted": counts[REFUTED],
            "inconclusive": counts[INCONCLUSIVE],
            "grounded_ratio": round(grounded / total, 4) if total else 0.0,
            "trustworthy": counts[REFUTED] == 0 and counts[INCONCLUSIVE] == 0 and total > 0,
            "results": results,
        }

    # -- claim handlers -----------------------------------------------------
    # Each returns (verdict, evidence_dict, detail_str).

    def _check_bytes_at(self, p: Dict[str, Any]):
        """Claim: the bytes at ``offset`` equal ``expected`` (hex)."""
        if "offset" not in p or "expected" not in p:
            raise ClaimError("bytes_at requires 'offset' and 'expected'")
        offset = _as_int(p["offset"])
        expected = _clean_hex(p["expected"])
        if offset < 0 or offset + len(expected) > len(self.data):
            return INCONCLUSIVE, {"file_size": len(self.data)}, "offset out of range"
        actual = self.data[offset : offset + len(expected)]
        evidence = {"offset": hex(offset), "actual": actual.hex(), "expected": expected.hex()}
        if actual == expected:
            return VERIFIED, evidence, "bytes match"
        return REFUTED, evidence, "bytes differ"

    def _check_pattern_present(self, p: Dict[str, Any]):
        """Claim: AOB ``pattern`` occurs (optionally at ``offset`` / ``count`` times)."""
        if "pattern" not in p:
            raise ClaimError("pattern_present requires 'pattern'")
        matches = pattern_scan(self.data, str(p["pattern"]))
        evidence = {"match_offsets": [hex(m) for m in matches[:64]], "match_count": len(matches)}
        if "offset" in p:
            want = _as_int(p["offset"])
            ok = want in matches
            evidence["expected_offset"] = hex(want)
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
        first = self.data.find(needle)
        all_offsets = []
        start = 0
        while True:
            idx = self.data.find(needle, start)
            if idx == -1:
                break
            all_offsets.append(idx)
            start = idx + 1
        evidence = {"found_offsets": [hex(o) for o in all_offsets[:64]], "occurrences": len(all_offsets)}
        if "offset" in p:
            want = _as_int(p["offset"])
            ok = want in all_offsets
            evidence["expected_offset"] = hex(want)
            return (VERIFIED if ok else REFUTED), evidence, (
                "string present at claimed offset" if ok else "string not at claimed offset"
            )
        if first != -1:
            return VERIFIED, evidence, "string present"
        return REFUTED, evidence, "string absent"

    def _check_instructions(self, p: Dict[str, Any]):
        """Claim: disassembling ``length`` bytes at ``offset`` yields ``mnemonics``.

        With ``mode='contains'`` the claimed mnemonics need only appear as an
        ordered subsequence; the default ``mode='exact'`` requires the full
        mnemonic sequence to match.
        """
        if "offset" not in p or "mnemonics" not in p:
            raise ClaimError("instructions requires 'offset' and 'mnemonics'")
        offset = _as_int(p["offset"])
        expected = [str(m).lower() for m in p["mnemonics"]]
        arch = str(p.get("arch", "x86_64"))
        mode = str(p.get("mode", "exact"))
        length = _as_int(p["length"]) if "length" in p else None
        if offset < 0 or offset >= len(self.data):
            return INCONCLUSIVE, {"file_size": len(self.data)}, "offset out of range"
        code = self.data[offset : offset + length] if length else self.data[offset:]
        base = _as_int(p["base"]) if "base" in p else 0x1000
        insns = Disassembler(arch=arch).disassemble(code, base_address=base)
        actual = [i.mnemonic.lower() for i in insns]
        evidence = {"actual_mnemonics": actual, "expected_mnemonics": expected}
        if mode == "contains":
            ok = _is_subsequence(expected, actual)
        else:
            ok = actual == expected
        return (VERIFIED if ok else REFUTED), evidence, f"mode={mode}"

    def _check_emulate_result(self, p: Dict[str, Any]):
        """Claim: emulating the code leaves registers at ``expect_registers``.

        Code comes from ``code`` (hex) or from ``offset``/``length`` into the
        binary. ``expect_registers`` maps register name to expected integer.
        """
        if "expect_registers" not in p:
            raise ClaimError("emulate_result requires 'expect_registers'")
        arch = str(p.get("arch", "x86_64"))
        base = _as_int(p["base"]) if "base" in p else 0x1000
        max_steps = _as_int(p["max_steps"]) if "max_steps" in p else 1000
        if "code" in p:
            code = _clean_hex(p["code"])
        elif "offset" in p:
            offset = _as_int(p["offset"])
            length = _as_int(p["length"]) if "length" in p else 64
            if offset < 0 or offset >= len(self.data):
                return INCONCLUSIVE, {"file_size": len(self.data)}, "offset out of range"
            code = self.data[offset : offset + length]
        else:
            raise ClaimError("emulate_result requires 'code' or 'offset'")

        emu = make_emulator(arch=arch, prefer=str(p.get("backend", "auto")))
        emu.load_code(code, base_address=base)
        state = emu.run(max_steps=max_steps)

        expect = {str(k).lower(): _as_int(v) for k, v in dict(p["expect_registers"]).items()}
        observed = {name: emu.reg_read(name) for name in expect}
        mismatches = {
            name: {"expected": hex(want), "actual": hex(observed[name])}
            for name, want in expect.items()
            if observed[name] != want
        }
        evidence = {
            "expect_registers": {k: hex(v) for k, v in expect.items()},
            "observed_registers": {k: hex(v) for k, v in observed.items()},
            "steps_executed": emu.steps_executed,
            "mismatches": mismatches,
            "backend": state.get("backend", "pure-python"),
        }
        if not mismatches:
            return VERIFIED, evidence, "register state matches"
        return REFUTED, evidence, f"{len(mismatches)} register(s) mismatched"

    def _check_protobuf_field(self, p: Dict[str, Any]):
        """Claim: Protobuf ``field`` has wire ``type`` and optionally ``value``."""
        if "field" not in p:
            raise ClaimError("protobuf_field requires 'field'")
        field_no = _as_int(p["field"])
        source = _clean_hex(p["data"]) if "data" in p else self.data
        tree = ProtobufDissector.dissect(source)
        key = f"field_{field_no}"
        if key not in tree:
            return REFUTED, {"present_fields": list(tree.keys())}, "field not present"
        entries = tree[key]
        evidence = {"field": key, "entries": entries}
        want_type = str(p["type"]).lower() if "type" in p else None
        if want_type is not None:
            types = {e.get("type") for e in entries}
            if want_type not in types:
                return REFUTED, evidence, f"types present: {sorted(t for t in types if t)}"
        if "value" in p:
            want = p["value"]
            found = any(_value_matches(e, want) for e in entries)
            if not found:
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
            # ELF/Mach-O group imports under "*"; honour the lib only as a linked-library check.
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
            "kind": claim.kind,
            "note": claim.note,
            "verdict": verdict,
            "detail": detail,
            "evidence": evidence,
            "params": claim.params,
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


def verify_claims(data: bytes, claims: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Convenience: verify a list of plain-dict claims against ``data``."""
    verifier = Verifier(data)
    parsed = [Claim.from_dict(c) for c in claims]
    return verifier.verify_all(parsed)
