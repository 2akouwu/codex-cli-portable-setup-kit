#!/usr/bin/env python3
"""Closed verification loop: the model proposes, the tools judge, it iterates.

This drives the deterministic :class:`~reverify.verifier.Verifier` automatically.
Given a binary and a goal in plain language, the agent asks a language model to
propose structured *claims* about the bytes, checks every claim with the
Verifier, feeds the refutations and their observed evidence back, and asks the
model to revise — round after round — until the reconstruction is grounded or a
round cap is reached.

Hardened against the ways a model games a verifier:

- The model never sees raw bytes beyond a small addressed header; it works from
  a keyed fact sheet and can *observe* values through the tools instead.
- Claims that restate the fact sheet, duplicates, self-referential inline code,
  and echoes of the tools' previous output all score zero, so "grounded" means
  the verified set actually says something (``information`` >= a threshold).
- Refuted claims come back with the address in every space and where the
  expected bytes really are, so the next proposal can fix the right parameter.
- ``samples`` > 1 draws several proposals per round and lets the verifier —
  not the model's confidence — select among them.

The language model is injected as a ``propose`` callable (``str -> str``) so the
loop is fully testable offline. :func:`openai_proposer` builds a default one.
"""

from __future__ import annotations

import json
import os
import re
import urllib.request
from typing import Any, Callable, Dict, List, Optional

try:  # package import
    from .verifier import Verifier, Claim, summarize, claim_key, OBSERVED, REFUTED, VERIFIED, _as_int, _clean_hex
    from .binary import parse_binary
except ImportError:  # flat import (CLI / tests)
    from verifier import Verifier, Claim, summarize, claim_key, OBSERVED, REFUTED, VERIFIED, _as_int, _clean_hex
    from binary import parse_binary

Proposer = Callable[[str], str]

CLAIM_KINDS_HELP = """Each claim is a JSON object: {"kind": <kind>, "params": {...}, "note": "<why>", "id"?: "<c1>", "depends_on"?: ["<c0>"], "observe"?: true}.
Offsets are FILE offsets unless params carry "space": "rva" or "va" (the verifier translates via the section table).
Kinds and params:
- bytes_at:        {"offset": <int>, "expected": "<hex>"}             (omit expected or set observe:true to read the bytes)
- u16_at/u32_at/u64_at: {"offset": <int>, "expected": <int>, "endian"?: "le|be"}   (typed reads; no endianness math needed)
- pattern_present: {"pattern": "<AOB hex with ?? wildcards>", "offset"?: <int>, "count"?: <int>}
- string_present:  {"value": "<text>", "offset"?: <int>, "encoding"?: "utf-8|utf-16le|..."}
- instructions:    {"offset": <int>, "length"?: <int>, "mnemonics": ["push","mov",...], "operands"?: ["rbp","rbp, rsp",...], "arch"?: "x86_64", "mode"?: "exact|contains"}
- emulate_result:  {"offset": <int>, "length"?: <int>, "arch"?: "x86_64", "expect_registers": {"rax": <int>}}   (offset into the binary; inline "code" not found in the binary scores zero)
- protobuf_field:  {"field": <int>, "type"?: "varint|string|...", "value"?: <any>, "offset"?: <int>}
- import_present:  {"function": "<symbol>", "lib"?: "<library>"}
- export_present:  {"name": "<symbol>"}
- section_present: {"name": "<.text|.data|...>", "virtual_address"?: <int>}"""

RULES = """RULES (how claims are scored):
- A claim that only restates BINARY FACTS scores ZERO. Say something the facts do not already say.
- Prefer specific, falsifiable claims: bytes_at with 4+ bytes beyond the shown header, typed u32_at/u64_at reads, instructions with mode=exact (add operands), emulate_result with an offset into the binary.
- Never do offset arithmetic or endianness conversion yourself: use typed reads and "space": "rva"/"va".
- Unsure of a value? Ask the tools: set "observe": true (or omit expected). The value is reported and added to the facts; assert it as a claim only if it supports the goal.
- Give claims an "id" and use "depends_on" when one rests on another (a struct layout on an image base), so a refuted root invalidates its dependents.
- Do not copy the tools' previously observed value back as an "expected" value; that is an echo and scores zero.
- The "note" field is never verified and is shown as unverified text."""


def _extract_ascii_strings(data: bytes, min_len: int = 5, limit: int = 20) -> List[str]:
    out = []
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data):
        out.append(m.group().decode("latin1", errors="ignore"))
        if len(out) >= limit:
            break
    return out


def _shift_signals(data: bytes, info) -> Dict[str, Any]:
    """Distribution-shift detectors: tell the model (and scorer) when priors are unreliable."""
    entropies = info.section_entropies(data) if info.sections else {}
    high = [n for n, e in entropies.items() if e >= 7.0]
    import_count = sum(len(v) for v in info.imports.values())
    entry_section = None
    if info.entrypoint is not None and info.sections:
        rva = info.entrypoint if info.format != "ELF" else None
        if info.format == "ELF" and info.image_base is not None:
            rva = info.entrypoint - info.image_base
        if rva is not None:
            sec = info.section_containing_rva(rva)
            entry_section = sec.name if sec else None
    end = max((s.offset + s.raw_size for s in info.sections), default=0)
    overlay = max(0, len(data) - end) if info.sections else 0
    packed_likely = bool(high) and import_count <= 8
    return {
        "section_entropy": entropies,
        "high_entropy_sections": high,
        "import_count": import_count,
        "entry_section": entry_section,
        "overlay_bytes": overlay,
        "packed_or_encrypted_likely": packed_likely,
        "caution": ("Priors about 'typical' code are unreliable here: high-entropy sections and few imports "
                    "suggest packing/encryption. Observe before asserting." if packed_likely else None),
    }


def binary_facts(data: bytes) -> Dict[str, Any]:
    """A compact, keyed, addressed snapshot of the binary to ground proposals."""
    facts: Dict[str, Any] = {
        "size": len(data),
        "magic_hex": data[:4].hex(),
        "first_32_bytes_hex": data[:32].hex(),
        "first_bytes": {hex(i): " ".join(f"{b:02x}" for b in data[i : i + 16]) for i in range(0, min(32, len(data)), 16)},
        "top_strings": _extract_ascii_strings(data[:65536]),
    }
    info = parse_binary(data)
    if info.format != "raw":
        facts["binary"] = info.summary()
        facts["imports"] = {k: v[:40] for k, v in info.imports.items()}
        facts["exports"] = info.exports[:40]
        facts["sections"] = [
            {
                "name": s.name,
                "file_offset": hex(s.offset),
                "rva": hex(s.virtual_address),
                "va": hex(info.image_base + s.virtual_address) if info.image_base is not None else None,
                "raw_size": s.raw_size,
                "virtual_size": s.virtual_size,
            }
            for s in info.sections
        ]
        facts["addressing"] = "Offsets default to file offsets. Use space:'rva' or 'va' to address by RVA/VA."
        facts["shift_signals"] = _shift_signals(data, info)
    return facts


def build_prompt(goal: str, facts: Dict[str, Any], feedback: str) -> str:
    parts = [
        "You are reconstructing facts about a binary. Propose claims that the "
        "deterministic tools can verify against the actual bytes.",
        "",
        f"GOAL: {goal}",
        "",
        "BINARY FACTS (ground truth; already known — restating them scores zero):",
        json.dumps(facts, indent=1, ensure_ascii=False),
        "",
        RULES,
        "",
        CLAIM_KINDS_HELP,
        "",
        "Output ONLY a JSON array of claim objects. No prose, no code fences.",
    ]
    if feedback:
        parts += ["", "PREVIOUS ROUND RESULTS — fix or replace what did not hold; propose new informative claims:", feedback]
    return "\n".join(parts)


def parse_claims(raw: str) -> List[Dict[str, Any]]:
    """Pull a JSON array of claim dicts out of a model response."""
    text = (raw or "").strip()
    if "```" in text:
        inner = text.split("```", 2)
        if len(inner) >= 2:
            body = inner[1]
            body = body[4:] if body.lower().startswith("json") else body
            text = body.strip()
    start, end = text.find("["), text.rfind("]")
    if start != -1 and end != -1 and end > start:
        text = text[start : end + 1]
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        data = [data]
    return [c for c in data if isinstance(c, dict) and "kind" in c]


def _compact_evidence(r: Dict[str, Any]) -> Dict[str, Any]:
    ev = r.get("evidence", {}) or {}
    keep = {}
    for k in ("address", "actual", "expected", "nearest_offset_of_expected", "mismatches",
              "observed_registers", "actual_mnemonics", "actual_operands", "present_fields",
              "imported_libs", "sections", "error", "self_referential"):
        if k in ev:
            keep[k] = ev[k]
    return keep


def format_feedback(report: Dict[str, Any]) -> str:
    lines = []
    for r in report["results"]:
        v = r["verdict"]
        if v == OBSERVED:
            continue  # folded into the facts
        if v == VERIFIED and r.get("weight", 0) > 0:
            continue
        label = f"{r['kind']}" + (f" id={r['id']}" if r.get("id") else "")
        if v == VERIFIED:
            why = "echo of previous tool output" if r.get("echoed") else ("duplicate" if r.get("duplicate") else "restates the fact sheet")
            lines.append(f"- TRIVIAL {label}: passed but weight 0 ({why}). Propose something the facts do not say.")
            continue
        ev = json.dumps(_compact_evidence(r), ensure_ascii=False)
        lines.append(f"- {v} {label}: {r['detail']}. evidence={ev}")
    need = report.get("min_information", 1.0)
    lines.append(
        f"- SCORE: information {report.get('information', 0)} of {need} needed; "
        f"trivial={report.get('trivial_verified', 0)} echoed={report.get('echoed', 0)} duplicates={report.get('duplicates', 0)}."
    )
    return "\n".join(lines)


# -- echo detection helpers ---------------------------------------------------

def _echo_key(r: Dict[str, Any]) -> Optional[str]:
    kind = r["kind"]
    ev = r.get("evidence", {}) or {}
    addr = ev.get("address") or {}
    off = addr.get("file_offset")
    if off is None:
        p = r.get("params", {})
        if "offset" in p:
            try:
                off = hex(_as_int(p["offset"]))
            except (ValueError, TypeError):
                return None
    if off is None:
        return None
    return f"{kind}@{off}"


def _actual_repr(r: Dict[str, Any]):
    kind, ev = r["kind"], r.get("evidence", {}) or {}
    if kind == "bytes_at":
        return str(ev.get("actual", "")).lower() or None
    if kind in ("u16_at", "u32_at", "u64_at"):
        return ev.get("actual")
    if kind == "instructions":
        return tuple(ev.get("actual_mnemonics") or ())
    if kind == "emulate_result":
        regs = ev.get("observed_registers") or ev.get("registers")
        return tuple(sorted((k, str(v).lower()) for k, v in (regs or {}).items())) or None
    return None


def _expected_repr(r: Dict[str, Any]):
    kind, p = r["kind"], r.get("params", {})
    try:
        if kind == "bytes_at" and p.get("expected"):
            return _clean_hex(p["expected"]).hex()
        if kind in ("u16_at", "u32_at", "u64_at") and "expected" in p:
            return hex(_as_int(p["expected"]))
        if kind == "instructions":
            return tuple(str(m).lower() for m in p.get("mnemonics", []))
        if kind == "emulate_result" and "expect_registers" in p:
            return tuple(sorted((str(k).lower(), hex(_as_int(v))) for k, v in dict(p["expect_registers"]).items()))
    except (ValueError, TypeError):
        return None
    return None


def _is_echo(kind: str, expected, actual) -> bool:
    if expected is None or actual is None:
        return False
    if kind == "instructions":
        return len(expected) > 0 and tuple(actual[: len(expected)]) == tuple(expected)
    if kind in ("u16_at", "u32_at", "u64_at"):
        try:
            return _as_int(expected) == _as_int(actual)
        except (ValueError, TypeError):
            return False
    return expected == actual


def _loc_key(obj: Claim) -> str:
    """Identity by kind + location, so a *revised* claim is not counted as dropped."""
    p = obj.params
    if "offset" in p:
        try:
            return f"{obj.kind}@{hex(_as_int(p['offset']))}"
        except (ValueError, TypeError):
            pass
    return claim_key(obj.kind, p)


class ReconstructionAgent:
    """Runs the propose -> verify -> revise loop until grounded or capped."""

    def __init__(
        self,
        data: bytes,
        propose: Proposer,
        max_rounds: int = 4,
        samples: int = 1,
        min_information: float = 1.0,
    ):
        self.data = data
        self.verifier = Verifier(data)
        self.propose = propose
        self.max_rounds = max(1, int(max_rounds))
        self.samples = max(1, int(samples))
        self.min_information = float(min_information)

    def run(self, goal: str) -> Dict[str, Any]:
        facts = binary_facts(self.data)
        facts["observed"] = {}
        history: List[Dict[str, Any]] = []
        feedback = ""
        grounded = False
        prev_keys: set = set()
        prev_actual: Dict[str, Any] = {}

        for rnd in range(1, self.max_rounds + 1):
            prompt = build_prompt(goal, facts, feedback)
            raw_claims: List[Dict[str, Any]] = []
            for _ in range(self.samples):
                raw_claims.extend(parse_claims(self.propose(prompt)))
            claim_objs: List[Claim] = []
            seen = set()
            for c in raw_claims:
                try:
                    obj = Claim.from_dict(c)
                except Exception:
                    continue
                k = claim_key(obj.kind, obj.params)
                if k in seen:
                    continue
                seen.add(k)
                claim_objs.append(obj)

            report = self.verifier.verify_all(claim_objs, facts=facts, min_information=self.min_information)

            # Echo detection: a claim that just parrots last round's observed value scores zero.
            echoed = 0
            for r in report["results"]:
                k = _echo_key(r)
                if k and k in prev_actual and _is_echo(r["kind"], _expected_repr(r), prev_actual[k]):
                    r["echoed"] = True
                    echoed += 1
            if echoed:
                report = summarize(report["results"], facts=facts, min_information=self.min_information)

            # Fold OBSERVED values into the facts; remember actuals for next round's echo check.
            new_actual: Dict[str, Any] = {}
            for r in report["results"]:
                k = _echo_key(r)
                act = _actual_repr(r)
                if k and r["verdict"] == OBSERVED and act is not None:
                    facts["observed"][k] = act if not isinstance(act, tuple) else list(act)
                if k and act is not None and r["verdict"] in (REFUTED, OBSERVED):
                    new_actual[k] = act

            keys_now = {_loc_key(o) for o in claim_objs}
            attrition = len(prev_keys - keys_now) if prev_keys else 0
            history.append({
                "round": rnd,
                "claims": [c for c in raw_claims],
                "report": report,
                "attrition": attrition,
                "echoed": echoed,
            })
            prev_keys, prev_actual = keys_now, new_actual
            if report["grounded"]:
                grounded = True
                break
            feedback = format_feedback(report)

        final = history[-1]["report"] if history else None
        return {
            "goal": goal,
            "grounded": grounded,
            "rounds_used": len(history),
            "information": final["information"] if final else 0.0,
            "verified_claims": [
                r for r in (final["results"] if final else []) if r["verdict"] == VERIFIED and r.get("weight", 0) > 0
            ] if grounded else [],
            "observed": dict(facts["observed"]),
            "history": history,
            "final_report": final,
        }


def openai_proposer(
    model: Optional[str] = None,
    base_url: Optional[str] = None,
    api_key: Optional[str] = None,
    temperature: float = 0.7,
    timeout: int = 60,
) -> Proposer:
    """Proposer backed by an OpenAI-compatible chat-completions API.

    Temperature defaults to 0.7: under thin evidence a low temperature just
    re-emits the prior's modal guess round after round; diversity plus the
    deterministic verifier as selector works better.
    """
    api_key = api_key or os.getenv("OPENAI_API_KEY")
    model = model or os.getenv("OPENAI_MODEL") or "gpt-4o"
    base_url = base_url or os.getenv("OPENAI_BASE_URL") or "https://api.openai.com/v1"
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY required for the live proposer (or inject your own).")

    def _propose(prompt: str) -> str:
        body = json.dumps({
            "model": model,
            "messages": [
                {"role": "system", "content": "You output only valid JSON arrays of claim objects."},
                {"role": "user", "content": prompt},
            ],
            "temperature": temperature,
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{base_url.rstrip('/')}/chat/completions",
            data=body,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data["choices"][0]["message"]["content"]

    return _propose


def demo_proposer(data: bytes) -> Proposer:
    """Offline proposer for ``reverify reconstruct --mock``.

    On a binary of 40+ bytes it asserts the real last 8 bytes (an informative
    claim beyond the shown header) and observes a value; on tiny inputs it can
    only restate the header, which the scorer correctly treats as trivial.
    """
    claims: List[Dict[str, Any]] = []
    if len(data) >= 40:
        off = len(data) - 8
        claims.append({"kind": "bytes_at", "params": {"offset": off, "expected": data[off:].hex()},
                       "note": "tail bytes (offline demo claim)", "id": "tail"})
        claims.append({"kind": "u32_at", "params": {"offset": 32}, "observe": True, "note": "read a value the facts do not show"})
    else:
        claims.append({"kind": "bytes_at", "params": {"offset": 0, "expected": data[:4].hex()},
                       "note": "file header (restates the facts; expect weight 0)"})

    def _propose(_prompt: str) -> str:
        return json.dumps(claims)

    return _propose
