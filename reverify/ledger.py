#!/usr/bin/env python3
"""Durable established-facts ledger: the state that survives a context reset.

Every agent harness surveyed (Claude Code, Codex CLI, OpenCode, Cline, Roo,
Gemini CLI, the Anthropic and OpenAI compaction APIs) handles a full context
window the same way: ask a model to summarize the transcript, drop the rest,
and accept the loss. That is unavoidable for free-form conversation, because
nothing in a transcript says which parts were *state* and which were chatter.

Reverify's loop can do better for itself, because it already draws that line:
the only things that matter are what the deterministic tools verified,
observed or proved — and what they refuted. Everything else (the model's prose,
its unverified guesses) was never trusted, so discarding it loses nothing. The
ledger writes exactly that state to disk after every round. A context window
can then be cleared, compacted, or the process restarted, and the next round
continues from the same grounded position — lossless *by construction*, not by
summary. Refutations are kept too, so a fresh context does not re-propose the
same wrong prior (the negative memory a summary usually drops).

Two views of one store:

- **on disk**: unbounded, one JSON file per binary keyed by SHA-256, atomic
  writes, under ``.reverify/ledger/`` (override with ``REVERIFY_LEDGER_DIR``);
- **in context**: a bounded projection (``established(max_facts)``) — most
  recent facts, with proof-grade facts pinned so they are never paged out.
  The hand-off itself is lazy: by default only a one-line index per binary is
  injected and the facts are pulled on demand, so recovering state never
  costs a large slice of the fresh context.

Nothing unverified is stored: claim notes (free text) are excluded on purpose.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Union

try:  # package import
    from .verifier import VERIFIED, REFUTED, OBSERVED, claim_key, _as_int, _clean_hex
    from .semantic import SEMANTIC_KINDS
except ImportError:  # flat import (CLI / tests)
    from verifier import VERIFIED, REFUTED, OBSERVED, claim_key, _as_int, _clean_hex
    from semantic import SEMANTIC_KINDS

SCHEMA = 1
DEFAULT_DIR = ".reverify"
ENV_DIR = "REVERIFY_LEDGER_DIR"

#: Strength tiers recorded per fact. Proof-grade facts are pinned in the context view.
PROVEN = "PROVEN"
TESTED = "TESTED"
DERIVED = "DERIVED"  # engine-derived (static analysis): function boundaries, call graph, xrefs
TIER_RANK = {PROVEN: 3, TESTED: 2, VERIFIED: 1, DERIVED: 1, OBSERVED: 0}
PINNED_RANK = 2  # PROVEN and TESTED never fall out of the bounded view

_EVIDENCE_KEEP = (
    "address", "actual", "expected", "nearest_offset_of_expected", "mismatches",
    "observed_registers", "actual_mnemonics", "actual_operands", "present_fields",
    "imported_libs", "sections", "error", "self_referential", "counterexample",
    "inputs_tested", "proof", "steps",
    "engine", "engine_version", "strength", "function", "inside_function", "nearest_function",
    "from_function", "to_function", "callee_count", "referenced_by", "reference_count",
)

LEDGER_INSTRUCTIONS = (
    "Reverify keeps a durable ledger per binary of everything its tools verified, observed, "
    "proved or refuted (re_verify_claim records automatically). After a context reset "
    "(/clear, compaction, or a new session) call re_ledger with the file path to restore the "
    "grounded state instead of re-deriving it (max_facts bounds how much comes back). Facts "
    "in the ledger are safe to build on; claims listed as known false must not be proposed again."
)


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _jsonable(value: Any) -> Any:
    if isinstance(value, tuple):
        return [_jsonable(v) for v in value]
    if isinstance(value, list):
        return [_jsonable(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


# -- result identity helpers (shared with the agent) --------------------------

def echo_key(r: Dict[str, Any]) -> Optional[str]:
    """Identity of a result by kind + file offset (``bytes_at@0x28``)."""
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


def actual_repr(r: Dict[str, Any]):
    """The value the tools actually read for a result, in a comparable form."""
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


def expected_repr(r: Dict[str, Any]):
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


def compact_evidence(r: Dict[str, Any]) -> Dict[str, Any]:
    ev = r.get("evidence", {}) or {}
    return {k: _jsonable(ev[k]) for k in _EVIDENCE_KEEP if k in ev}


def _value_suffix(r: Dict[str, Any]) -> str:
    """What the fact *says*, so a fresh context learns the value, not just that a check passed."""
    kind = r["kind"]
    ev = r.get("evidence", {}) or {}
    p = r.get("params", {}) or {}
    try:
        if kind == "bytes_at" and ev.get("actual"):
            return f" = {ev['actual']}"
        if kind in ("u16_at", "u32_at", "u64_at") and ev.get("actual") is not None:
            return f" = {ev['actual']}"
        if kind == "instructions" and ev.get("actual_mnemonics"):
            return " = " + " ".join(str(m) for m in list(ev["actual_mnemonics"])[:8])
        if kind == "emulate_result" and ev.get("observed_registers"):
            return " = " + json.dumps(_jsonable(ev["observed_registers"]), sort_keys=True)
        if kind == "pattern_present" and p.get("pattern"):
            return f" pattern={p['pattern']}"
        if kind == "string_present" and p.get("value") is not None:
            return f" value={p['value']!r}"
        if kind in ("import_present", "pe_import"):
            lib = p.get("lib") or p.get("dll") or "?"
            return f" {lib}!{p.get('function', '?')}"
        if kind in ("export_present", "section_present"):
            return f" {p.get('name', '?')}"
        if kind == "prove_equiv":
            return f" {p.get('a')} == {p.get('b')}"
        if kind == "behavior_equiv" and p.get("expr"):
            return f" expr={p['expr']}"
        if kind == "protobuf_field":
            return f" field={p.get('field')}"
        if kind in ("function_at", "reachable_from_entry"):
            fn = ev.get("function") or ev.get("inside_function") or {}
            if fn.get("name"):
                return f" {fn['name']}" + (f" size={fn['size']}" if fn.get("size") else "")
            return ""
        if kind == "calls":
            a = (ev.get("from_function") or {}).get("name")
            b = (ev.get("to_function") or {}).get("name")
            if a and b:
                return f" {a} -> {b}"
            return f" {a} callees={ev.get('callee_count')}" if a else ""
        if kind == "references":
            names = [r.get("function") for r in (ev.get("referenced_by") or []) if r.get("function")]
            return (" from " + ", ".join(dict.fromkeys(names[:4]))) if names else ""
    except (TypeError, ValueError):
        return ""
    return ""


def describe_established(r: Dict[str, Any]) -> str:
    """A short line for the established-facts ledger — only grounded results go here."""
    ev = r.get("evidence", {}) or {}
    addr = (ev.get("address") or {}).get("file_offset")
    loc = f" @ {addr}" if addr else ""
    return f"{r['kind']}{loc}: {r.get('detail', '')}{_value_suffix(r)}"[:160]


def describe_refuted(r: Dict[str, Any]) -> str:
    """A short line for a refutation: what was claimed and what the tools found instead."""
    ev = r.get("evidence", {}) or {}
    p = r.get("params", {}) or {}
    addr = (ev.get("address") or {}).get("file_offset")
    loc = f" @ {addr}" if addr else ""
    expected = ev.get("expected", p.get("expected"))
    actual = ev.get("actual")
    if expected is not None and actual is not None:
        body = f"claimed {expected}, tools read {actual}"
    else:
        body = str(r.get("detail", ""))
        suffix = _value_suffix(r)
        if suffix and body.find(suffix.strip()) == -1:
            body += suffix
    return f"{r['kind']}{loc}: {body}"[:160]


def tier_of(r: Dict[str, Any]) -> Optional[str]:
    """Which tier a result earns, or None if it is not a fact (refuted, trivial, ...)."""
    v = r.get("verdict")
    if v == OBSERVED:
        return OBSERVED
    if v == VERIFIED and float(r.get("weight", 0) or 0) > 0:
        kind = r.get("kind")
        if kind == "prove_equiv":
            return PROVEN
        if kind in ("behavior_equiv", "exebench"):
            return TESTED
        if kind in SEMANTIC_KINDS:
            return DERIVED
        return VERIFIED
    return None


def ledger_dir(directory: Union[str, Path, None] = None) -> Path:
    """``<directory or $REVERIFY_LEDGER_DIR or .reverify>/ledger``."""
    base = Path(directory or os.environ.get(ENV_DIR) or DEFAULT_DIR)
    return base / "ledger"


class Ledger:
    """Grounded facts about one binary, persisted per round.

    ``path`` is ``None`` for an in-memory ledger (the default inside
    :class:`~reverify.agent.ReconstructionAgent` when no directory is given);
    the API is identical, ``save()`` is just a no-op.
    """

    def __init__(self, sha256: str, size: int, path: Optional[Path] = None):
        self.sha256 = sha256
        self.size = int(size)
        self.path = Path(path) if path else None
        self.facts: List[Dict[str, Any]] = []
        self.refuted: List[Dict[str, Any]] = []
        self.observed: Dict[str, Any] = {}
        self.runs: List[Dict[str, Any]] = []
        self.paths: List[str] = []
        self.goals: List[str] = []
        self.created = _now()
        self.updated = self.created
        self.load_error: Optional[str] = None
        self._fact_index: Dict[str, int] = {}
        self._refuted_index: Dict[str, int] = {}

    # -- construction ----------------------------------------------------------

    @classmethod
    def for_bytes(
        cls,
        data: bytes,
        directory: Union[str, Path, None] = None,
        persist: bool = True,
        file_path: Optional[str] = None,
    ) -> "Ledger":
        sha = hashlib.sha256(data).hexdigest()
        path = ledger_dir(directory) / f"{sha[:24]}.json" if persist else None
        led = cls(sha, len(data), path)
        if path is not None and path.exists():
            led.load()
        if file_path:
            led.remember_path(file_path)
        return led

    @classmethod
    def for_file(
        cls, file_path: Union[str, Path], directory: Union[str, Path, None] = None, persist: bool = True
    ) -> "Ledger":
        with open(file_path, "rb") as f:
            data = f.read()
        return cls.for_bytes(data, directory=directory, persist=persist, file_path=str(file_path))

    @classmethod
    def load_path(cls, path: Union[str, Path]) -> "Ledger":
        led = cls("", 0, Path(path))
        led.load()
        return led

    # -- persistence -----------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "sha256": self.sha256,
            "size": self.size,
            "paths": list(self.paths),
            "goals": list(self.goals),
            "created": self.created,
            "updated": self.updated,
            "facts": list(self.facts),
            "refuted": list(self.refuted),
            "observed": dict(self.observed),
            "runs": list(self.runs),
        }

    def _reindex(self) -> None:
        self._fact_index = {e["key"]: i for i, e in enumerate(self.facts)}
        self._refuted_index = {e["key"]: i for i, e in enumerate(self.refuted)}

    def load(self) -> bool:
        if self.path is None or not self.path.exists():
            return False
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                doc = json.load(f)
            if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
                found = doc.get("schema") if isinstance(doc, dict) else type(doc).__name__
                raise ValueError(f"unsupported ledger schema: {found}")
        except (OSError, ValueError) as exc:
            # A corrupt ledger must never take the loop down: start empty, keep the evidence.
            self.load_error = str(exc)
            try:
                self.path.replace(self.path.with_suffix(".corrupt.json"))
            except OSError:
                pass
            return False
        self.sha256 = str(doc.get("sha256") or self.sha256)
        self.size = int(doc.get("size") or self.size)
        self.paths = [str(p) for p in doc.get("paths", [])]
        self.goals = [str(g) for g in doc.get("goals", [])]
        self.created = str(doc.get("created") or self.created)
        self.updated = str(doc.get("updated") or self.updated)
        self.facts = [e for e in doc.get("facts", []) if isinstance(e, dict) and "key" in e]
        self.refuted = [e for e in doc.get("refuted", []) if isinstance(e, dict) and "key" in e]
        self.observed = dict(doc.get("observed", {}) or {})
        self.runs = list(doc.get("runs", []))
        self._reindex()
        return True

    def save(self) -> Optional[Path]:
        """Atomic checkpoint (temp file + rename). No-op for an in-memory ledger."""
        if self.path is None:
            return None
        self.updated = _now()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self.to_dict(), indent=1, ensure_ascii=False, default=str)
        fd, tmp = tempfile.mkstemp(prefix=self.path.name + ".", suffix=".tmp", dir=str(self.path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(payload)
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except OSError:
                    pass
        return self.path

    def clear(self) -> None:
        self.facts, self.refuted, self.observed, self.runs = [], [], {}, []
        self._reindex()
        if self.path is not None and self.path.exists():
            self.path.unlink()

    # -- recording -------------------------------------------------------------

    def remember_path(self, file_path: str) -> None:
        p = str(file_path)
        if p not in self.paths:
            self.paths.append(p)
            self.paths = self.paths[-8:]

    def start_run(self, goal: str, session: Optional[str] = None) -> None:
        if goal and goal not in self.goals:
            self.goals.append(goal)
            self.goals = self.goals[-20:]
        self.runs.append({"session": session, "goal": goal, "started": _now(), "rounds": 0,
                          "grounded": False, "information": 0.0})
        self.runs = self.runs[-20:]

    def finish_run(self, rounds: int, grounded: bool, information: float) -> None:
        if self.runs:
            self.runs[-1].update({"rounds": int(rounds), "grounded": bool(grounded),
                                  "information": float(information), "finished": _now()})

    def fact_keys(self) -> set:
        return set(self._fact_index)

    def record(
        self,
        results: Union[Dict[str, Any], Iterable[Dict[str, Any]]],
        rnd: Optional[int] = None,
        goal: Optional[str] = None,
        session: Optional[str] = None,
    ) -> Dict[str, int]:
        """Fold a verification report (or its results) into the ledger.

        Only grounded results enter as facts: VERIFIED with weight (trivial,
        duplicate, echoed and already-known claims weigh zero and are skipped),
        OBSERVED values, and the proof/test tiers. REFUTED claims are kept as
        known-false. INCONCLUSIVE and INVALIDATED record nothing. The claim's
        free-text ``note`` is never stored.
        """
        if isinstance(results, dict) and "results" in results:
            results = results["results"]
        added = {"facts": 0, "observed": 0, "refuted": 0}
        for r in results:
            if not isinstance(r, dict) or "kind" not in r:
                continue
            key = claim_key(r["kind"], r.get("params", {}) or {})
            tier = tier_of(r)
            if tier is not None:
                entry: Dict[str, Any] = {
                    "key": key,
                    "kind": r["kind"],
                    "tier": tier,
                    "weight": round(float(r.get("weight", 0) or 0), 3),
                    "location": ((r.get("evidence") or {}).get("address") or {}).get("file_offset"),
                    "detail": str(r.get("detail", ""))[:200],
                    "line": describe_established(r),
                    "claim": {"kind": r["kind"], "params": _jsonable(r.get("params", {}) or {})},
                    "evidence": compact_evidence(r),
                    "round": rnd,
                    "session": session,
                    "ts": _now(),
                }
                if tier == OBSERVED:
                    k, act = echo_key(r), actual_repr(r)
                    if k is None or act is None:
                        continue
                    value = _jsonable(act)
                    entry["line"] = f"observed {k} = {value}"
                    entry["value"] = value
                    key = entry["key"] = f"observed:{k}"
                    if k not in self.observed:
                        added["observed"] += 1
                    self.observed[k] = value
                if key in self._fact_index:
                    # keep the first record; upgrade the weight if a stronger check landed
                    old = self.facts[self._fact_index[key]]
                    if entry["weight"] > float(old.get("weight", 0) or 0):
                        old["weight"] = entry["weight"]
                    continue
                self._fact_index[key] = len(self.facts)
                self.facts.append(entry)
                added["facts"] += 1
            elif r.get("verdict") == REFUTED:
                if key in self._refuted_index:
                    continue
                ev = r.get("evidence") or {}
                self._refuted_index[key] = len(self.refuted)
                self.refuted.append({
                    "key": key,
                    "kind": r["kind"],
                    "location": (ev.get("address") or {}).get("file_offset"),
                    "detail": str(r.get("detail", ""))[:200],
                    "line": describe_refuted(r),
                    "claim": {"kind": r["kind"], "params": _jsonable(r.get("params", {}) or {})},
                    "evidence": compact_evidence(r),
                    "round": rnd,
                    "session": session,
                    "ts": _now(),
                })
                added["refuted"] += 1
        if goal and goal not in self.goals:
            self.goals.append(goal)
            self.goals = self.goals[-20:]
        self.updated = _now()
        return added

    # -- views -----------------------------------------------------------------

    def established(self, max_facts: int = 40) -> List[str]:
        """The bounded context view: the most recent ``max_facts`` fact lines,
        chronological, with proof/test-tier facts pinned so they never page out."""
        n = max(1, int(max_facts))
        if len(self.facts) <= n:
            return [e["line"] for e in self.facts]
        pinned = [i for i, e in enumerate(self.facts) if TIER_RANK.get(e.get("tier"), 0) >= PINNED_RANK]
        chosen = set(pinned[-n:]) | set(range(len(self.facts) - n, len(self.facts)))
        # drop the oldest unpinned entries until the view fits
        for i in sorted(chosen):
            if len(chosen) <= n:
                break
            if i not in pinned:
                chosen.discard(i)
        return [self.facts[i]["line"] for i in sorted(chosen)[-n:]]

    def known_false(self, limit: int = 12) -> List[str]:
        """Most recent refutations, so a fresh context does not re-propose them."""
        if limit <= 0:
            return []
        return [e["line"] for e in self.refuted[-int(limit):]]

    def counts(self) -> Dict[str, int]:
        c = {PROVEN: 0, TESTED: 0, VERIFIED: 0, DERIVED: 0, OBSERVED: 0}
        for e in self.facts:
            t = e.get("tier", VERIFIED)
            c[t] = c.get(t, 0) + 1
        return {"facts": len(self.facts), "proven": c[PROVEN], "tested": c[TESTED],
                "verified": c[VERIFIED], "derived": c[DERIVED], "observed": c[OBSERVED],
                "refuted": len(self.refuted)}

    def summary(self) -> Dict[str, Any]:
        out = {
            "path": str(self.path) if self.path else None,
            "sha256": self.sha256,
            "size": self.size,
            "paths": list(self.paths),
            "goals": list(self.goals),
            "updated": self.updated,
            "runs": len(self.runs),
            **self.counts(),
        }
        if self.load_error:
            out["load_error"] = self.load_error
        return out

    def label(self) -> str:
        return self.paths[-1] if self.paths else f"sha256 {self.sha256[:16]}"

    def index_line(self) -> str:
        """One line: enough for a fresh context to know the ledger exists and how to pull it."""
        c = self.counts()
        how = (f"load with re_ledger or `reverify ledger \"{self.paths[-1]}\"`" if self.paths
               else "load with re_ledger (pass the file path)")
        return (f"reverify ledger: {self.label()} - {c['facts']} grounded facts "
                f"({c['proven']} proven, {c['tested']} tested, {c['verified']} verified, {c['derived']} derived, {c['observed']} observed), "
                f"{c['refuted']} refuted; {how}.")

    def context_text(self, max_facts: int = 40, max_false: int = 8) -> str:
        """Plain text for injection into a fresh context (hooks, ``re_ledger``)."""
        c = self.counts()
        head = (f"reverify ledger for {self.label()} ({self.size} bytes): {c['facts']} grounded facts "
                f"({c['proven']} proven, {c['tested']} tested, {c['verified']} verified, {c['derived']} derived, {c['observed']} observed), "
                f"{c['refuted']} refuted. Facts below were checked by the tools and are safe to build on; "
                f"nothing else from earlier work should be assumed.")
        lines = [head]
        if self.goals:
            lines.append("Goals so far: " + "; ".join(self.goals[-3:]))
        est = self.established(max_facts)
        if est:
            lines.append("ESTABLISHED:")
            lines += [f"- {e}" for e in est]
        kf = self.known_false(max_false)
        if kf:
            lines.append("KNOWN FALSE (already refuted; do not propose again):")
            lines += [f"- {e}" for e in kf]
        return "\n".join(lines)


# -- directory-level helpers (CLI ``reverify ledger --context``, hooks) --------

def list_ledgers(directory: Union[str, Path, None] = None) -> List[Ledger]:
    d = ledger_dir(directory)
    if not d.is_dir():
        return []
    out = []
    for p in sorted(d.glob("*.json")):
        if p.name.endswith(".corrupt.json"):
            continue
        led = Ledger.load_path(p)
        if led.facts or led.refuted or led.observed:
            out.append(led)
    out.sort(key=lambda l: l.updated, reverse=True)
    return out


def context_for_directory(
    directory: Union[str, Path, None] = None,
    mode: str = "index",
    max_facts: int = 30,
    max_false: int = 8,
    max_chars: int = 8000,
    limit: int = 5,
) -> str:
    """Everything grounded so far in this project, bounded, as plain text.

    ``mode="index"`` (the default for hooks) emits one line per binary — the
    hand-off costs a few dozen tokens and the facts are pulled on demand.
    ``mode="facts"`` inlines the bounded fact view. Empty string when there is
    nothing, so a hook injects nothing rather than noise.
    """
    parts: List[str] = []
    total = 0
    for led in list_ledgers(directory)[: max(1, int(limit))]:
        txt = led.index_line() if mode == "index" else led.context_text(max_facts=max_facts, max_false=max_false)
        if total + len(txt) > max_chars and parts:
            break
        parts.append(txt[:max_chars])
        total += len(txt)
    return ("\n" if mode == "index" else "\n\n").join(parts)


def hook_config(command: str = "reverify ledger --context") -> Dict[str, Any]:
    """A Claude Code ``SessionStart`` hook that re-injects the ledger index after
    compaction, ``/clear`` or resume — the ledger is written at verify time, so
    nothing has to happen at the moment the context fills up."""
    return {
        "hooks": {
            "SessionStart": [
                {
                    "matcher": "compact|clear|resume",
                    "hooks": [{"type": "command", "command": command}],
                }
            ]
        }
    }
