#!/usr/bin/env python3
"""Rollover controller: fresh context on the model's own signal, with a *verified* hand-off.

Long tasks outgrow a context window. Every harness deals with that by summarizing
the transcript and continuing — and the summary is written by the model, so whatever
the model believed (including its own hallucinations) is carried forward as if it were
state. The Ralph-loop pattern (a fresh process per iteration, state in files) avoids the
summary but still trusts the model's notes.

This controller runs a goal as a sequence of **sessions**, each a fresh context:

- the model works through a small JSON protocol (propose claims, take notes, update its
  hand-off, ask for a rollover, declare done);
- every claim is judged by :class:`~reverify.verifier.Verifier` and recorded in the
  :class:`~reverify.ledger.Ledger` — the only memory of *facts* across sessions;
- a rollover happens when the **model asks for it**, when the session's token budget is
  reached, or when the loop shows drift (restatements / echoes dominate);
- the hand-off written into the next session is **verified by construction**: its
  ESTABLISHED and KNOWN FALSE come from the ledger, never from the model, and the
  model's own notes travel labelled *unverified*.

The user of such a loop never clears anything and never sees a transcript re-injected:
each session opens with the fact sheet, a one-line ledger index and a bounded hand-off.

Drivers (swap the model, keep the protocol): :class:`OpenAIChatDriver` (any
OpenAI-compatible endpoint), :class:`MockDriver` (scripted, for tests) and
:class:`ClaudeAgentSDKDriver` (the Claude Agent SDK, runs on a Claude Code login).
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import re
import tempfile
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

try:  # package import
    from .agent import RULES, CLAIM_KINDS_HELP, binary_facts, compact_facts, parse_claims
    from .ledger import Ledger, ledger_dir
    from .verifier import Verifier, Claim, claim_key, summarize, VERIFIED, REFUTED, OBSERVED
except ImportError:  # flat import (CLI / tests)
    from agent import RULES, CLAIM_KINDS_HELP, binary_facts, compact_facts, parse_claims
    from ledger import Ledger, ledger_dir
    from verifier import Verifier, Claim, claim_key, summarize, VERIFIED, REFUTED, OBSERVED

PROTOCOL = """You work on a binary through deterministic tools that judge every claim. Each turn reply with ONE JSON object, no prose outside it:
- {"claims": [<claim objects>]}            the tools verify them; results come back next turn
- {"note": "<text>"}                        a working note; stored as UNVERIFIED, never as a fact
- {"checkpoint": {"done": [..], "todo": [..], "decisions": [..], "next_step": ".."}}
                                            update your hand-off (facts you write here are NOT trusted; only verified claims become facts)
- {"rollover": true, "reason": ".."}        your context is getting long or confused: the controller saves the hand-off and restarts you fresh
- {"done": true, "summary": ".."}           the goal is met
You may combine "claims" with "checkpoint" in one object. Work in small steps: observe what you need, then assert checkable claims."""


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


# -- hand-off record -----------------------------------------------------------

class Checkpoint:
    """The hand-off between sessions. Facts come from the ledger; the model's part is labelled."""

    def __init__(self, goal: str):
        self.goal = goal
        self.done: List[str] = []
        self.todo: List[str] = []
        self.decisions: List[str] = []     # model-written: unverified
        self.next_step: str = ""
        self.notes: List[str] = []         # model-written: unverified
        self.sessions: int = 0
        self.rollovers: List[Dict[str, Any]] = []
        self.updated = _now()

    def merge(self, update: Dict[str, Any]) -> None:
        for key in ("done", "todo", "decisions"):
            vals = update.get(key)
            if isinstance(vals, list):
                items = [str(v)[:200] for v in vals if str(v).strip()]
                current = getattr(self, key)
                for it in items:
                    if it not in current:
                        current.append(it)
                setattr(self, key, current[-40:])
        if update.get("next_step"):
            self.next_step = str(update["next_step"])[:300]
        self.updated = _now()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "goal": self.goal, "done": self.done, "todo": self.todo, "decisions": self.decisions,
            "next_step": self.next_step, "notes": self.notes[-20:], "sessions": self.sessions,
            "rollovers": self.rollovers[-20:], "updated": self.updated,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Checkpoint":
        cp = cls(str(d.get("goal", "")))
        cp.done = [str(x) for x in d.get("done", [])]
        cp.todo = [str(x) for x in d.get("todo", [])]
        cp.decisions = [str(x) for x in d.get("decisions", [])]
        cp.next_step = str(d.get("next_step", ""))
        cp.notes = [str(x) for x in d.get("notes", [])]
        cp.sessions = int(d.get("sessions", 0))
        cp.rollovers = list(d.get("rollovers", []))
        cp.updated = str(d.get("updated", _now()))
        return cp

    def handoff_text(self, max_items: int = 12) -> str:
        """Bounded, labelled: what the previous session of the model declared (not verified)."""
        lines = ["HAND-OFF from your previous session (written by you; UNVERIFIED unless it also appears in ESTABLISHED):"]
        if self.done:
            lines.append("done: " + "; ".join(self.done[-max_items:]))
        if self.todo:
            lines.append("todo: " + "; ".join(self.todo[-max_items:]))
        if self.decisions:
            lines.append("decisions (unverified): " + "; ".join(self.decisions[-max_items:]))
        if self.notes:
            lines.append("notes (unverified): " + "; ".join(self.notes[-6:]))
        if self.next_step:
            lines.append("next step: " + self.next_step)
        if self.rollovers:
            last = self.rollovers[-1]
            lines.append(f"last rollover: {last.get('reason', '?')} (session {last.get('session')}, {last.get('tokens')} tokens)")
        return "\n".join(lines)


# -- drivers ---------------------------------------------------------------------

class MockDriver:
    """Scripted replies per session for offline tests: ``scripts[session][turn]``."""

    name = "mock"

    def __init__(self, scripts: List[List[str]]):
        self.scripts = scripts
        self.calls: List[Dict[str, Any]] = []
        self._session = -1
        self._turn = 0

    def start(self, system: str, opening: str) -> str:
        self._session += 1
        self._turn = 0
        self.calls.append({"session": self._session, "system": system, "opening": opening})
        return self._reply()

    def send(self, message: str) -> str:
        self.calls[-1].setdefault("messages", []).append(message)
        return self._reply()

    def _reply(self) -> str:
        script = self.scripts[min(self._session, len(self.scripts) - 1)]
        reply = script[min(self._turn, len(script) - 1)]
        self._turn += 1
        return reply

    def tokens(self) -> Optional[int]:
        return None


class OpenAIChatDriver:
    """One chat-completions conversation per session; ``start`` resets the message list."""

    name = "openai"

    def __init__(self, model: Optional[str] = None, base_url: Optional[str] = None,
                 api_key: Optional[str] = None, temperature: float = 0.5, timeout: int = 90):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.model = model or os.getenv("OPENAI_MODEL") or "gpt-4o"
        self.base_url = (base_url or os.getenv("OPENAI_BASE_URL") or "https://api.openai.com/v1").rstrip("/")
        self.temperature = temperature
        self.timeout = timeout
        self.messages: List[Dict[str, str]] = []
        self._tokens: Optional[int] = None
        if not self.api_key:
            raise RuntimeError("OPENAI_API_KEY required for the OpenAI driver (or use --driver mock / claude)")

    def start(self, system: str, opening: str) -> str:
        self.messages = [{"role": "system", "content": system}, {"role": "user", "content": opening}]
        return self._complete()

    def send(self, message: str) -> str:
        self.messages.append({"role": "user", "content": message})
        return self._complete()

    def _complete(self) -> str:
        body = json.dumps({"model": self.model, "messages": self.messages, "temperature": self.temperature}).encode("utf-8")
        req = urllib.request.Request(f"{self.base_url}/chat/completions", data=body,
                                     headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        text = data["choices"][0]["message"]["content"]
        self.messages.append({"role": "assistant", "content": text})
        usage = data.get("usage") or {}
        self._tokens = int(usage.get("total_tokens") or 0) or None
        return text

    def tokens(self) -> Optional[int]:
        return self._tokens


class ClaudeAgentSDKDriver:
    """One Claude Agent SDK session per rollover session (fresh context each time).

    Runs on a Claude Code login — no API key. Requires ``pip install claude-agent-sdk``.
    Tools are disabled: the controller is the only judge, the model only talks JSON.
    """

    name = "claude"

    def __init__(self, model: Optional[str] = None, max_turns: int = 40):
        try:
            import claude_agent_sdk  # noqa: F401
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError("claude-agent-sdk not installed: pip install claude-agent-sdk") from exc
        self.model = model
        self.max_turns = max_turns
        self._session_id: Optional[str] = None
        self._system = ""
        self._tokens: Optional[int] = None

    def _query(self, prompt: str, resume: Optional[str]) -> str:
        import asyncio
        from claude_agent_sdk import query, ClaudeAgentOptions, AssistantMessage, ResultMessage, TextBlock

        async def go() -> str:
            opts = ClaudeAgentOptions(system_prompt=self._system, allowed_tools=[], max_turns=self.max_turns,
                                      resume=resume, model=self.model)
            text: List[str] = []
            async for msg in query(prompt=prompt, options=opts):
                if isinstance(msg, AssistantMessage):
                    for block in msg.content:
                        if isinstance(block, TextBlock):
                            text.append(block.text)
                elif isinstance(msg, ResultMessage):
                    self._session_id = msg.session_id
                    usage = getattr(msg, "usage", None) or {}
                    if isinstance(usage, dict):
                        self._tokens = int(usage.get("input_tokens", 0) or 0) + int(usage.get("output_tokens", 0) or 0)
            return "\n".join(text)

        return asyncio.run(go())

    def start(self, system: str, opening: str) -> str:
        self._system = system
        self._session_id = None
        return self._query(opening, resume=None)

    def send(self, message: str) -> str:
        return self._query(message, resume=self._session_id)

    def tokens(self) -> Optional[int]:
        return self._tokens


# -- the controller ---------------------------------------------------------------

def _parse_action(text: str) -> Dict[str, Any]:
    """The model's JSON object; tolerant of code fences and stray prose."""
    raw = (text or "").strip()
    if "```" in raw:
        parts = raw.split("```")
        for part in parts[1::2]:
            body = part[4:] if part.lower().startswith("json") else part
            raw = body.strip()
            break
    protocol_keys = ("claims", "note", "checkpoint", "rollover", "done")
    if raw.startswith("["):                      # a bare array of claims
        claims = parse_claims(raw)
        if claims:
            return {"claims": claims}
    start, end = raw.find("{"), raw.rfind("}")
    if start != -1 and end > start:
        try:
            obj = json.loads(raw[start : end + 1])
            if isinstance(obj, dict):
                if "kind" in obj and not any(k in obj for k in protocol_keys):
                    return {"claims": [obj]}     # a single bare claim object
                return obj
        except json.JSONDecodeError:
            pass
    claims = parse_claims(text)
    return {"claims": claims} if claims else {"note": raw[:300]}


class Orchestrator:
    """Runs a goal across fresh-context sessions with a verified hand-off.

    ``session_tokens``: budget per session (estimated as chars/4 unless the driver reports
    usage); ``drift_window``/``drift_ratio``: roll over when, over the last N judged
    turns, restatements (trivial + echoed + known) make up at least this share of claims.
    """

    def __init__(
        self,
        data: bytes,
        driver,
        *,
        directory: Union[str, Path, None] = None,
        file_path: Optional[str] = None,
        session_tokens: int = 60_000,
        max_sessions: int = 6,
        max_turns: int = 30,
        max_facts: int = 40,
        prompt_budget: int = 40_000,
        drift_window: int = 4,
        drift_ratio: float = 0.75,
        min_information: float = 1.0,
        task_id: Optional[str] = None,
    ):
        self.data = data
        self.driver = driver
        self.verifier = Verifier(data)
        self.ledger = Ledger.for_bytes(data, directory=directory, file_path=file_path, persist=directory is not None)
        self.session_tokens = int(session_tokens)
        self.max_sessions = max(1, int(max_sessions))
        self.max_turns = max(1, int(max_turns))
        self.max_facts = int(max_facts)
        self.prompt_budget = int(prompt_budget)
        self.drift_window = max(1, int(drift_window))
        self.drift_ratio = float(drift_ratio)
        self.min_information = float(min_information)
        self.task_id = task_id or uuid.uuid4().hex[:8]
        base = Path(directory) if directory else None
        self.task_dir = (ledger_dir(base).parent / "sessions" / self.task_id) if base else None
        self.checkpoint: Optional[Checkpoint] = None
        self.log: List[Dict[str, Any]] = []

    # -- persistence ---------------------------------------------------------------

    def _load_checkpoint(self, goal: str) -> Checkpoint:
        if self.task_dir and (self.task_dir / "checkpoint.json").exists():
            try:
                with open(self.task_dir / "checkpoint.json", "r", encoding="utf-8") as f:
                    cp = Checkpoint.from_dict(json.load(f))
                if cp.goal == goal:
                    return cp
            except (OSError, ValueError):
                pass
        return Checkpoint(goal)

    def _save_checkpoint(self) -> Optional[Path]:
        if not self.task_dir or self.checkpoint is None:
            return None
        self.task_dir.mkdir(parents=True, exist_ok=True)
        path = self.task_dir / "checkpoint.json"
        payload = json.dumps(self.checkpoint.to_dict(), indent=1, ensure_ascii=False)
        fd, tmp = tempfile.mkstemp(prefix="checkpoint.", suffix=".tmp", dir=str(self.task_dir))
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(payload)
        os.replace(tmp, path)
        hist = self.task_dir / "history"
        hist.mkdir(exist_ok=True)
        with open(hist / f"session-{self.checkpoint.sessions:03d}.json", "w", encoding="utf-8") as f:
            f.write(payload)
        return path

    # -- prompts -------------------------------------------------------------------

    def _opening(self, goal: str, facts: Dict[str, Any], feedback: str = "") -> str:
        established = self.ledger.established(self.max_facts)
        known_false = self.ledger.known_false()
        view, _steps, _size = compact_facts(facts, self.prompt_budget, goal, established, feedback, known_false)
        parts = [
            f"GOAL: {goal}",
            "",
            "BINARY FACTS (ground truth; restating them scores zero):",
            json.dumps(view, indent=1, ensure_ascii=False),
            "",
            self.ledger.index_line(),
        ]
        if established:
            parts += ["", "ESTABLISHED (verified by the tools in earlier sessions; the ONLY facts you may build on):",
                      "\n".join(f"- {e}" for e in established)]
        if known_false:
            parts += ["", "KNOWN FALSE (refuted earlier; do not propose again):", "\n".join(f"- {e}" for e in known_false)]
        if self.checkpoint and (self.checkpoint.done or self.checkpoint.todo or self.checkpoint.decisions or self.checkpoint.notes):
            parts += ["", self.checkpoint.handoff_text()]
        parts += ["", RULES, "", CLAIM_KINDS_HELP, "", PROTOCOL]
        if feedback:
            parts += ["", feedback]
        return "\n".join(parts)

    def _feedback(self, report: Dict[str, Any]) -> str:
        lines = []
        for r in report["results"]:
            v = r["verdict"]
            label = r["kind"] + (f" id={r['id']}" if r.get("id") else "")
            if v == VERIFIED and r.get("weight", 0) > 0:
                lines.append(f"- VERIFIED {label} (weight {r['weight']}) -> recorded in the ledger")
            elif v == VERIFIED:
                why = "already established" if r.get("known") else ("echo" if r.get("echoed") else ("duplicate" if r.get("duplicate") else "restates the facts"))
                lines.append(f"- TRIVIAL {label}: passed but weight 0 ({why})")
            elif v == OBSERVED:
                ev = r.get("evidence") or {}
                lines.append(f"- OBSERVED {label}: {ev.get('actual', r.get('detail', ''))}")
            else:
                ev = r.get("evidence") or {}
                keep = {k: ev[k] for k in ("actual", "expected", "address", "nearest_offset_of_expected", "actual_mnemonics", "candidates", "callees") if k in ev}
                lines.append(f"- {v} {label}: {r['detail']}. evidence={json.dumps(keep, ensure_ascii=False)[:400]}")
        c = self.ledger.counts()
        lines.append(f"- LEDGER: {c['facts']} facts, {c['refuted']} refuted; information this batch {report.get('information', 0)}")
        return "RESULTS:\n" + "\n".join(lines)

    # -- run -------------------------------------------------------------------------

    def run(self, goal: str) -> Dict[str, Any]:
        self.checkpoint = self._load_checkpoint(goal)
        facts = binary_facts(self.data)
        facts["observed"] = dict(self.ledger.observed)
        done = False
        summary = ""
        session_no = 0
        while session_no < self.max_sessions and not done:
            session_no += 1
            self.checkpoint.sessions += 1
            self.ledger.start_run(goal, f"{self.task_id}:{session_no}")
            opening = self._opening(goal, facts)
            system = "You output only JSON objects as instructed. Never assume facts you did not verify."
            transcript_chars = len(system) + len(opening)
            reply = self.driver.start(system, opening)
            transcript_chars += len(reply)
            turns = 0
            recent: List[Dict[str, int]] = []
            rolled = None
            while True:
                turns += 1
                action = _parse_action(reply)
                feedback_parts: List[str] = []
                if isinstance(action.get("checkpoint"), dict):
                    self.checkpoint.merge(action["checkpoint"])
                if action.get("note"):
                    self.checkpoint.notes.append(str(action["note"])[:300])
                claims_raw = action.get("claims") or []
                if claims_raw:
                    objs: List[Claim] = []
                    seen = set()
                    for c in claims_raw:
                        try:
                            obj = Claim.from_dict(c)
                        except Exception:
                            continue
                        k = claim_key(obj.kind, obj.params)
                        if k not in seen:
                            seen.add(k)
                            objs.append(obj)
                    report = self.verifier.verify_all(objs, facts=facts, min_information=self.min_information)
                    known_keys = self.ledger.fact_keys()
                    known = 0
                    for r in report["results"]:
                        if r["verdict"] == VERIFIED and claim_key(r["kind"], r.get("params", {})) in known_keys:
                            r["known"] = True
                            known += 1
                    if known:
                        report = summarize(report["results"], facts=facts, min_information=self.min_information)
                    for r in report["results"]:
                        if r["verdict"] == OBSERVED:
                            ev = r.get("evidence") or {}
                            addr = (ev.get("address") or {}).get("file_offset")
                            if addr is not None and "actual" in ev:
                                facts["observed"][f"{r['kind']}@{addr}"] = ev["actual"]
                    added = self.ledger.record(report["results"], rnd=turns, goal=goal, session=f"{self.task_id}:{session_no}")
                    self.ledger.save()
                    restated = report.get("trivial_verified", 0) + report.get("echoed", 0) + report.get("known", 0)
                    recent.append({"claims": report["total_claims"], "restated": restated, "refuted": report["refuted"]})
                    feedback_parts.append(self._feedback(report))
                    self.log.append({"session": session_no, "turn": turns, "claims": report["total_claims"],
                                     "verified": report["verified"], "refuted": report["refuted"], "restated": restated,
                                     "added": added})
                if action.get("done"):
                    done = True
                    summary = str(action.get("summary", ""))[:500]
                    break
                # -- rollover decision: the model's signal, the budget, or drift ----------
                est = self.driver.tokens() or _estimate_tokens(" " * transcript_chars)
                window = recent[-self.drift_window:]
                drift = (len(window) >= self.drift_window and sum(w["claims"] for w in window) > 0 and
                         sum(w["restated"] for w in window) / max(1, sum(w["claims"] for w in window)) >= self.drift_ratio)
                if action.get("rollover"):
                    rolled = {"reason": f"model: {str(action.get('reason', ''))[:160]}", "tokens": est}
                elif est >= self.session_tokens:
                    rolled = {"reason": f"budget: {est} tokens >= {self.session_tokens}", "tokens": est}
                elif drift:
                    rolled = {"reason": "drift: restatements dominate the last turns", "tokens": est}
                elif turns >= self.max_turns:
                    rolled = {"reason": f"turn cap {self.max_turns}", "tokens": est}
                if rolled:
                    rolled["session"] = session_no
                    self.checkpoint.rollovers.append(rolled)
                    break
                status = (f"STATUS: session {session_no}, turn {turns}, ~{est} of {self.session_tokens} tokens used; "
                          f"reply {{\"rollover\": true}} when your context feels long or confused, {{\"done\": true}} when the goal is met.")
                message = "\n\n".join(feedback_parts + [status]) if feedback_parts else status
                transcript_chars += len(message)
                reply = self.driver.send(message)
                transcript_chars += len(reply)
            self.ledger.finish_run(turns, done, self.ledger.counts()["facts"])
            self.ledger.save()
            self._save_checkpoint()
        c = self.ledger.counts()
        return {
            "goal": goal,
            "done": done,
            "summary": summary,
            "sessions": session_no,
            "rollovers": list(self.checkpoint.rollovers),
            "facts": c["facts"],
            "refuted": c["refuted"],
            "established": self.ledger.established(self.max_facts),
            "known_false": self.ledger.known_false(),
            "checkpoint": self.checkpoint.to_dict(),
            "checkpoint_path": str(self.task_dir / "checkpoint.json") if self.task_dir else None,
            "ledger_path": str(self.ledger.path) if self.ledger.path else None,
            "log": self.log,
        }


def demo_scripts(data: bytes) -> List[List[str]]:
    """Two scripted sessions for ``reverify orchestrate --driver mock``: the first verifies a
    real window, refutes a guess, writes an unverified decision and asks for a rollover; the
    second receives the verified hand-off, observes a value and finishes."""
    n = len(data)
    off = max(40, n // 2)
    good = {"kind": "bytes_at", "params": {"offset": off, "expected": data[off : off + 8].hex()}, "note": "a window specific to this file"}
    bad = {"kind": "bytes_at", "params": {"offset": min(n - 8, off + 32), "expected": "ffffffffffffffff"}, "note": "guess"}
    return [
        [
            json.dumps({"claims": [good, bad], "checkpoint": {"done": ["read the header"], "decisions": ["the check is at the guessed offset (unverified)"], "next_step": "observe the value after it"}}),
            json.dumps({"rollover": True, "reason": "context is getting long; hand off"}),
        ],
        [
            json.dumps({"claims": [{"kind": "u32_at", "params": {"offset": 32}, "observe": True}], "checkpoint": {"todo": ["map the rest"]}}),
            json.dumps({"done": True, "summary": "grounded what could be grounded; the guess was refuted and is on record"}),
        ],
    ]


def make_driver(name: str, **kwargs):
    name = (name or "mock").lower()
    if name == "openai":
        return OpenAIChatDriver(**kwargs)
    if name in ("claude", "claude-sdk", "sdk"):
        return ClaudeAgentSDKDriver(**{k: v for k, v in kwargs.items() if k in ("model", "max_turns")})
    raise ValueError(f"unknown driver '{name}' (openai | claude | mock)")
