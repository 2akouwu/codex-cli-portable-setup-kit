#!/usr/bin/env python3
"""Closed verification loop: the model proposes, the tools judge, it iterates.

This drives the deterministic :class:`~reverify.verifier.Verifier` automatically.
Given a binary and a goal in plain language, the agent asks a language model to
propose structured *claims* about the bytes, checks every claim with the
Verifier, feeds the refutations and their observed evidence back, and asks the
model to revise — round after round — until the reconstruction is fully grounded
or a round cap is reached.

The model never gets to assert a structural fact; it can only propose one, and
the deterministic tools decide. That is the whole point of Reverify, now closed
into a loop.

The language model is injected as a ``propose`` callable (``str -> str``) so the
loop is fully testable offline. :func:`openai_proposer` builds a default one from
the usual ``OPENAI_*`` environment, but any callable that maps a prompt to a
model response works.
"""

from __future__ import annotations

import json
import os
import re
import urllib.request
from typing import Any, Callable, Dict, List, Optional

try:  # package import
    from .verifier import Verifier, Claim
    from .pe_parser import PEParser, BinaryParseError
except ImportError:  # flat import (CLI / tests)
    from verifier import Verifier, Claim
    from pe_parser import PEParser, BinaryParseError

Proposer = Callable[[str], str]

CLAIM_KINDS_HELP = """Each claim is a JSON object: {"kind": <kind>, "params": {...}, "note": "<why>"}.
Supported kinds and their params:
- bytes_at:        {"offset": <int>, "expected": "<hex>"}
- pattern_present: {"pattern": "<AOB hex with ?? wildcards>", "offset"?: <int>, "count"?: <int>}
- string_present:  {"value": "<text>", "offset"?: <int>, "encoding"?: "utf-8|utf-16le|..."}
- instructions:    {"offset": <int>, "length"?: <int>, "mnemonics": ["push","mov",...], "arch"?: "x86_64", "mode"?: "exact|contains"}
- emulate_result:  {"code": "<hex>" | "offset": <int>, "arch"?: "x86", "expect_registers": {"eax": <int>}}
- protobuf_field:  {"field": <int>, "type"?: "varint|string|...", "value"?: <any>, "data"?: "<hex>"}
- pe_import:       {"dll"?: "<name>", "function": "<symbol>"}"""


def _extract_ascii_strings(data: bytes, min_len: int = 5, limit: int = 20) -> List[str]:
    out = []
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data):
        out.append(m.group().decode("latin1", errors="ignore"))
        if len(out) >= limit:
            break
    return out


def binary_facts(data: bytes) -> Dict[str, Any]:
    """A compact, factual snapshot of the binary to ground the model's proposals."""
    facts: Dict[str, Any] = {
        "size": len(data),
        "magic_hex": data[:4].hex(),
        "first_32_bytes_hex": data[:32].hex(),
        "top_strings": _extract_ascii_strings(data[:65536]),
    }
    if data[:2] == b"MZ":
        try:
            facts["pe"] = PEParser(data).summary()
        except BinaryParseError as exc:
            facts["pe_error"] = str(exc)
    return facts


def build_prompt(goal: str, facts: Dict[str, Any], feedback: str) -> str:
    parts = [
        "You are reconstructing facts about a binary. Propose claims that the "
        "deterministic tools can verify against the actual bytes. Only propose "
        "claims you believe the bytes support.",
        "",
        f"GOAL: {goal}",
        "",
        "BINARY FACTS (ground truth):",
        json.dumps(facts, indent=2, ensure_ascii=False),
        "",
        CLAIM_KINDS_HELP,
        "",
        "Output ONLY a JSON array of claim objects. No prose, no code fences.",
    ]
    if feedback:
        parts += [
            "",
            "PREVIOUS ROUND RESULTS — revise or replace the claims that did not hold:",
            feedback,
        ]
    return "\n".join(parts)


def parse_claims(raw: str) -> List[Dict[str, Any]]:
    """Pull a JSON array of claim dicts out of a model response."""
    text = raw.strip()
    if "```" in text:
        # take the content of the first fenced block
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


def format_feedback(report: Dict[str, Any]) -> str:
    lines = []
    for r in report["results"]:
        if r["verdict"] == "VERIFIED":
            continue
        ev = json.dumps(r.get("evidence", {}), ensure_ascii=False)
        note = f" ({r['note']})" if r.get("note") else ""
        lines.append(f"- {r['verdict']} {r['kind']}{note}: {r['detail']}. observed={ev}")
    if not lines:
        return "All claims verified."
    return "\n".join(lines)


class ReconstructionAgent:
    """Runs the propose -> verify -> revise loop until grounded or capped."""

    def __init__(self, data: bytes, propose: Proposer, max_rounds: int = 4):
        self.data = data
        self.verifier = Verifier(data)
        self.propose = propose
        self.max_rounds = max(1, int(max_rounds))

    def run(self, goal: str) -> Dict[str, Any]:
        facts = binary_facts(self.data)
        history: List[Dict[str, Any]] = []
        feedback = ""
        grounded = False

        for rnd in range(1, self.max_rounds + 1):
            prompt = build_prompt(goal, facts, feedback)
            raw = self.propose(prompt)
            claims = parse_claims(raw)
            report = self.verifier.verify_all([Claim.from_dict(c) for c in claims])
            grounded = report["trustworthy"]  # >0 claims, all VERIFIED, none refuted/inconclusive
            history.append({"round": rnd, "claims": claims, "report": report})
            if grounded:
                break
            feedback = format_feedback(report)

        final = history[-1]["report"] if history else None
        return {
            "goal": goal,
            "grounded": grounded,
            "rounds_used": len(history),
            "verified_claims": [
                r for h in history for r in h["report"]["results"] if r["verdict"] == "VERIFIED"
            ] if grounded else [],
            "history": history,
            "final_report": final,
        }


def openai_proposer(
    model: Optional[str] = None,
    base_url: Optional[str] = None,
    api_key: Optional[str] = None,
    temperature: float = 0.1,
    timeout: int = 60,
) -> Proposer:
    """Build a proposer backed by an OpenAI-compatible chat-completions API."""
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
    """An offline proposer that claims the binary's real first bytes.

    Trivially grounded in one round — used by ``reverify reconstruct --mock`` to
    demonstrate the loop end-to-end without a network call.
    """
    head = data[:4].hex()

    def _propose(_prompt: str) -> str:
        return json.dumps([
            {"kind": "bytes_at", "params": {"offset": 0, "expected": head},
             "note": "file header (offline demo claim)"}
        ])

    return _propose
