#!/usr/bin/env python3
"""Claude Code without compaction: fresh sessions with a file hand-off, on the model's own signal.

Claude Code's built-in compaction rewrites the conversation into a model-written summary
and keeps working in the same session. Whatever the model believed - including its own
mistakes - travels forward as if it were state. This module applies the reverify rule to
an interactive Claude Code session instead: **state lives in files, the conversation is a
cache**. Nothing is summarized in-band; the session is replaced, and the successor starts
from files plus the user's *verbatim* task statement.

Pieces (all stdlib, no reverify import, so the hooks start fast):

- ``stop``           Stop hook. Measures the live context from the session transcript (the
                     last assistant usage). When it crosses the threshold - or when the model
                     asked for a rollover with ``request`` - it blocks the stop once and tells
                     the model to write the hand-off *file* (fixed sections, labelled
                     UNVERIFIED) and update its memory index. On the next stop it checks that
                     the file was really written and well-formed and, only then, issues a
                     rollover receipt carrying the transcript hash and the verbatim user
                     anchors. If the model did not write it, nothing happens (fail closed)
                     and the guard re-arms further up.
- ``session-start``  SessionStart hook. Prints one pointer line when a hand-off exists, so a
                     fresh session pulls details on demand instead of loading them all.
- ``request``        Run by the model (``reverify rollover request --reason ...``): asks for a
                     rollover at the end of the current turn regardless of size - the same
                     ``{"rollover": true}`` signal the orchestrator uses.
- ``run``            The launcher: ``reverify rollover run -- <claude args>`` starts Claude Code,
                     waits for a receipt, checks that no user message slipped in meanwhile,
                     ends the session and starts a fresh one whose first message points at
                     the hand-off and quotes the original task verbatim. The old transcript
                     stays on disk as an audit trail and is never resumed. Without the
                     launcher (remote / bridge sessions) the receipt is informational and the
                     next new session picks the hand-off up.
- ``install`` / ``uninstall``  Write / remove the two hooks in ``~/.claude/settings.json`` and
                     turn built-in auto-compaction off / back on (backup kept next to it).
- ``status``         Tokens, threshold, guard state and hand-off for a session.

Every decision is appended to ``<state dir>/events.jsonl`` (block, receipt, skipped,
rollover) so a rollover can be audited after the fact.

Environment: ``REVERIFY_ROLLOVER_TOKENS`` (threshold, default 200k; 0 disables),
``REVERIFY_ROLLOVER_STEP`` (re-arm step, default 100k), ``REVERIFY_ROLLOVER_STATE_DIR``
(default ``~/.claude/rollover``), ``REVERIFY_ROLLOVER_DEBUG`` (diagnostics on stderr).

Every hook path fails open: on any error it exits 0 and stays silent, so a bug here can
never wedge a session. Every *rollover* path fails closed: no hand-off, a malformed one, a
user message in flight, an unknown receipt schema or a rollover too soon after the previous
one all mean "keep the current session".
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

RECEIPT_SCHEMA = 1
DEFAULT_THRESHOLD = 200_000
DEFAULT_STEP = 100_000
DEFAULT_MIN_INTERVAL = 120.0          # seconds between two rollovers of one launcher
HANDOFF_NAME = "rollover-handoff.md"
HANDOFF_MAX_BYTES = 24 * 1024
ANCHOR_MAX_CHARS = 1200
TAIL_BYTES = 4 * 1024 * 1024
HOOK_MARKERS = ("claude_rollover.py", "rollover_guard.py")

ENV_TOKENS = "REVERIFY_ROLLOVER_TOKENS"
ENV_STEP = "REVERIFY_ROLLOVER_STEP"
ENV_STATE_DIR = "REVERIFY_ROLLOVER_STATE_DIR"
ENV_SETTINGS = "REVERIFY_ROLLOVER_SETTINGS"
ENV_LAUNCH_ID = "REVERIFY_ROLLOVER_LAUNCH_ID"
ENV_DEBUG = "REVERIFY_ROLLOVER_DEBUG"
ENV_SESSION = "CLAUDE_CODE_SESSION_ID"


# --------------------------------------------------------------------------- small utils


def configure_streams() -> None:
    """Hook hosts read stdout as UTF-8; a legacy Windows code page must not garble it."""
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


def debug(message: str) -> None:
    if os.environ.get(ENV_DEBUG):
        print(f"[reverify rollover] {message}", file=sys.stderr)


def parse_tokens(value: Any, default: int) -> int:
    """Accept 200k / 0.2m / 200000; blank or garbage -> default."""
    if value is None:
        return default
    text = str(value).strip().lower().replace("_", "").replace(",", "")
    if not text:
        return default
    try:
        if text.endswith("m"):
            return int(round(float(text[:-1]) * 1_000_000))
        if text.endswith("k"):
            return int(round(float(text[:-1]) * 1_000))
        return int(round(float(text)))
    except ValueError:
        return default


def threshold_tokens() -> int:
    return parse_tokens(os.environ.get(ENV_TOKENS), DEFAULT_THRESHOLD)


def step_tokens() -> int:
    step = parse_tokens(os.environ.get(ENV_STEP), DEFAULT_STEP)
    return step if step > 0 else DEFAULT_STEP


def state_dir() -> Path:
    override = os.environ.get(ENV_STATE_DIR)
    if override:
        return Path(override)
    return Path.home() / ".claude" / "rollover"


def settings_path() -> Path:
    override = os.environ.get(ENV_SETTINGS)
    if override:
        return Path(override)
    return Path.home() / ".claude" / "settings.json"


def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(text: str) -> Optional[float]:
    """ISO-8601 (with Z or offset) -> epoch seconds; None when unparsable."""
    if not text:
        return None
    try:
        value = text.strip()
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        parsed = _dt.datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=_dt.timezone.utc)
        return parsed.timestamp()
    except ValueError:
        return None


def fmt_k(tokens: Optional[int]) -> str:
    return "?" if tokens is None else f"{tokens / 1000:.0f}k"


def read_hook_input() -> Dict[str, Any]:
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    data = json.loads(raw)
    return data if isinstance(data, dict) else {}


def emit(value: Dict[str, Any]) -> None:
    print(json.dumps(value, ensure_ascii=False))


def _write_json(path: Path, value: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def _read_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def log_event(kind: str, **fields: Any) -> None:
    """Append-only audit trail; never raises."""
    try:
        path = state_dir() / "events.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        record = {"at": now_iso(), "event": kind}
        record.update(fields)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception as exc:  # pragma: no cover - audit must not break the hook
        debug(f"log failed: {exc!r}")


# --------------------------------------------------------------------------- transcript


def _usage_tokens(usage: Dict[str, Any]) -> int:
    total = 0
    for key in ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens", "output_tokens"):
        value = usage.get(key)
        if isinstance(value, (int, float)):
            total += int(value)
    return total


def _tail_lines(path: Path) -> List[bytes]:
    size = path.stat().st_size
    with path.open("rb") as handle:
        if size > TAIL_BYTES:
            handle.seek(size - TAIL_BYTES)
            return handle.read().split(b"\n")[1:]
        return handle.read().split(b"\n")


def _records(lines: List[bytes], needle: bytes, reverse: bool = True):
    ordered = reversed(lines) if reverse else lines
    for line in ordered:
        if needle not in line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict):
            yield record


def context_tokens(transcript_path: Any) -> Optional[int]:
    """Live context of the main conversation = the last assistant usage in the transcript."""
    if not transcript_path:
        return None
    path = Path(transcript_path)
    if not path.is_file():
        return None
    for lines in (_tail_lines(path), path.read_bytes().split(b"\n")):
        for record in _records(lines, b'"assistant"'):
            if record.get("type") != "assistant" or record.get("isSidechain") is True:
                continue
            message = record.get("message")
            if not isinstance(message, dict) or not isinstance(message.get("usage"), dict):
                continue
            tokens = _usage_tokens(message["usage"])
            if tokens > 0:
                return tokens
        if path.stat().st_size <= TAIL_BYTES:
            break
    return None


def _human_text(record: Dict[str, Any]) -> Optional[str]:
    """The text of a real user message; None for tool results, meta and local-command echoes."""
    if record.get("type") != "user" or record.get("isSidechain") is True or record.get("isMeta") is True:
        return None
    if record.get("toolUseResult") is not None:
        return None
    message = record.get("message")
    if not isinstance(message, dict):
        return None
    content = message.get("content")
    text = ""
    if isinstance(content, str):
        text = content
    elif isinstance(content, list):
        parts = [b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text"]
        if any(isinstance(b, dict) and b.get("type") == "tool_result" for b in content):
            return None
        text = "\n".join(p for p in parts if isinstance(p, str))
    text = text.strip()
    if not text or text.startswith("<"):
        return None
    return text


def user_message_after(transcript_path: Any, since_epoch: float) -> bool:
    """True when a real user message (not a tool result) landed after ``since_epoch``."""
    if not transcript_path:
        return False
    path = Path(transcript_path)
    if not path.is_file():
        return False
    for record in _records(_tail_lines(path), b'"user"'):
        stamp = parse_iso(str(record.get("timestamp", "")))
        if stamp is None:
            continue
        if stamp < since_epoch:
            break
        if _human_text(record) is not None:
            return True
    return False


def transcript_anchors(transcript_path: Any) -> Dict[str, Any]:
    """Verbatim first and latest user messages plus a hash of the transcript at this moment.

    The anchors are what keeps objective A from drifting into B across rollovers: the
    successor is shown the user's own words, not the model's paraphrase of them.
    """
    result: Dict[str, Any] = {"first_user_message": None, "last_user_message": None,
                              "transcript_sha256": None, "transcript_bytes": None}
    if not transcript_path:
        return result
    path = Path(transcript_path)
    if not path.is_file():
        return result
    data = path.read_bytes()
    result["transcript_sha256"] = hashlib.sha256(data).hexdigest()
    result["transcript_bytes"] = len(data)
    lines = data.split(b"\n")
    for record in _records(lines, b'"user"', reverse=False):
        text = _human_text(record)
        if text is not None:
            result["first_user_message"] = text[:ANCHOR_MAX_CHARS]
            break
    for record in _records(lines, b'"user"'):
        text = _human_text(record)
        if text is not None:
            result["last_user_message"] = text[:ANCHOR_MAX_CHARS]
            break
    return result


# --------------------------------------------------------------------------- hand-off location & shape


def memory_dir_for(transcript_path: Any) -> Optional[Path]:
    """Claude Code keeps auto-memory next to the transcripts: <project dir>/memory."""
    if not transcript_path:
        return None
    candidate = Path(transcript_path).resolve().parent / "memory"
    return candidate if candidate.is_dir() else None


def handoff_path_for(transcript_path: Any, cwd: Any = None) -> Path:
    memory_dir = memory_dir_for(transcript_path)
    if memory_dir is not None:
        return memory_dir / HANDOFF_NAME
    return Path(str(cwd) if cwd else ".").resolve() / ".claude" / HANDOFF_NAME


def validate_handoff(path: Path, not_before: float) -> Optional[str]:
    """None when the hand-off is usable; otherwise the reason it is not."""
    if not path.is_file():
        return "hand-off file missing"
    stat = path.stat()
    if stat.st_mtime < not_before - 1.0:
        return "hand-off file was not rewritten after the block"
    if stat.st_size > HANDOFF_MAX_BYTES:
        return f"hand-off larger than {HANDOFF_MAX_BYTES} bytes"
    if stat.st_size == 0:
        return "hand-off file is empty"
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return f"hand-off unreadable: {exc}"
    headings = [line for line in text.splitlines() if line.startswith("## ")]
    if len(headings) < 3:
        return "hand-off has fewer than 3 sections"
    return None


# --------------------------------------------------------------------------- state, requests, receipts


def _safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in value)[:128] or "unknown"


def state_path(session_id: str) -> Path:
    return state_dir() / (_safe_name(session_id) + ".json")


def request_path(session_id: str) -> Path:
    return state_dir() / "requests" / (_safe_name(session_id) + ".json")


def receipt_path(key: str) -> Path:
    return state_dir() / "receipts" / (_safe_name(key) + ".json")


def load_state(session_id: str, threshold: int) -> Dict[str, Any]:
    state: Dict[str, Any] = {
        "session_id": session_id,
        "next_trigger": threshold,
        "pending": False,
        "blocked_at": None,
        "blocked_epoch": None,
        "blocked_tokens": None,
        "blocks": 0,
        "rollovers": 0,
        "handoff_path": None,
        "last_outcome": None,
    }
    saved = _read_json(state_path(session_id))
    if saved:
        state.update(saved)
    return state


def save_state(state: Dict[str, Any]) -> None:
    _write_json(state_path(str(state.get("session_id", "unknown"))), state)


def write_request(session_id: str, reason: str) -> Path:
    path = request_path(session_id)
    _write_json(path, {"session_id": session_id, "reason": reason[:300], "requested_at": now_iso()})
    return path


def pop_request(session_id: str) -> Optional[Dict[str, Any]]:
    path = request_path(session_id)
    data = _read_json(path)
    if data is None:
        return None
    try:
        path.unlink()
    except OSError:
        pass
    return data


def write_receipt(session_id: str, transcript: Any, handoff: Path, tokens: Optional[int],
                  reason: str, launch_id: Optional[str]) -> Path:
    receipt: Dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "session_id": session_id,
        "launch_id": launch_id,
        "transcript_path": str(transcript) if transcript else None,
        "handoff_path": str(handoff),
        "context_tokens": tokens,
        "reason": reason,
        "written_at": now_iso(),
        "written_epoch": time.time(),
    }
    receipt.update(transcript_anchors(transcript))
    path = receipt_path(launch_id or session_id)
    _write_json(path, receipt)
    return path


# --------------------------------------------------------------------------- the guard (Stop hook)

HANDOFF_TEMPLATE = """# Rollover hand-off
written: {when} · session: {session} · context: {tokens}
## Task and goal (one line) + constraints or preferences the user stated
## Decisions the user made (one reason each; include "don't" / "not yet")
## Done / in progress / not done
## Identifiers and paths, verbatim (commits, tags, PR/issue numbers, CI run ids, file paths, commands to re-run)
## Verification status (test counts and results, baseline numbers, which environment ran, which did not)
## Waiting on the user / waiting on external results (background jobs, CI)
## Next step
(This file is the model's own notes = UNVERIFIED. Verified facts live only in the memory files and the reverify ledger. Mark anything uncertain as uncertain; never fill gaps.)"""


def build_reason(tokens: Optional[int], threshold: int, handoff: Path, session_id: str,
                 has_memory_dir: bool, request: Optional[Dict[str, Any]]) -> str:
    if request is not None:
        why = "You asked for a rollover" + (f' ("{request.get("reason")}")' if request.get("reason") else "") + "."
    else:
        why = f"This conversation's context is at {fmt_k(tokens)} (threshold {fmt_k(threshold)})."
    memory_line = (
        "3. Add one pointer line to MEMORY.md in the same folder (e.g. `- [Rollover hand-off](rollover-handoff.md) — <one-line task>`); update it if it exists."
        if has_memory_dir
        else "3. Put the file's path into whichever memory index you maintain."
    )
    template = HANDOFF_TEMPLATE.format(when=now_iso(), session=session_id, tokens=fmt_k(tokens))
    return (
        f"[reverify rollover] {why} Built-in compaction is off. Before this turn ends, hand off to files, "
        "then finish your reply as you normally would.\n"
        "Rule: state lives in files, the conversation is a cache. Do not restate or summarize in the conversation, "
        "and do not tell the user about context, quality, cleanup, or any /clear or /compact action.\n\n"
        "1. Write this milestone's conclusions into the relevant memory topic file (update existing files; do not re-copy what is already there).\n"
        f"2. Overwrite the hand-off file `{handoff}` with exactly these sections, one page at most, nothing else:\n"
        + "\n".join("   " + line for line in template.splitlines())
        + f"\n{memory_line}\n"
        "4. If this session used reverify (ledger or re_checkpoint), call re_checkpoint save once with the same content.\n"
        "5. Then close with what you were going to tell the user, without mentioning any of the above."
    )


def run_stop(payload: Dict[str, Any], env: Optional[Dict[str, str]] = None) -> int:
    env = os.environ if env is None else env
    threshold = threshold_tokens()
    if threshold <= 0:
        debug("disabled (threshold 0)")
        return 0
    session_id = str(payload.get("session_id") or env.get(ENV_SESSION) or "unknown")
    transcript = payload.get("transcript_path")
    tokens = context_tokens(transcript)
    state = load_state(session_id, threshold)
    step = step_tokens()
    request = pop_request(session_id)

    if state.get("pending"):
        # We blocked the previous stop. Did the model actually write a usable hand-off?
        handoff = Path(str(state.get("handoff_path") or handoff_path_for(transcript, payload.get("cwd"))))
        problem = validate_handoff(handoff, float(state.get("blocked_epoch") or 0.0))
        base = state.get("blocked_tokens") or tokens or 0
        state["pending"] = False
        state["next_trigger"] = max(int(base), tokens or 0) + step
        state["released_at"] = now_iso()
        if problem is None:
            receipt = write_receipt(session_id, transcript, handoff, tokens,
                                    str(state.get("trigger_reason") or "threshold"), env.get(ENV_LAUNCH_ID))
            state["rollovers"] = int(state.get("rollovers", 0)) + 1
            state["last_outcome"] = "receipt"
            state["last_receipt"] = str(receipt)
            log_event("receipt", session=session_id, tokens=tokens, receipt=str(receipt), handoff=str(handoff),
                      launch_id=env.get(ENV_LAUNCH_ID))
            debug(f"hand-off ok; receipt {receipt}")
        else:
            state["last_outcome"] = "handoff_rejected: " + problem
            log_event("handoff_rejected", session=session_id, tokens=tokens, problem=problem, handoff=str(handoff))
            debug(f"no receipt (fail closed): {problem}")
        save_state(state)
        return 0

    triggered_by_request = request is not None
    if not triggered_by_request and (tokens is None or tokens < int(state.get("next_trigger", threshold))):
        debug(f"{tokens} < {state.get('next_trigger')} -> allow")
        return 0

    handoff = handoff_path_for(transcript, payload.get("cwd"))
    reason = ("request: " + str(request.get("reason") or "")).rstrip(": ") if request else "threshold"
    state.update({
        "pending": True,
        "blocked_at": now_iso(),
        "blocked_epoch": time.time(),
        "blocked_tokens": tokens,
        "blocks": int(state.get("blocks", 0)) + 1,
        "handoff_path": str(handoff),
        "trigger_reason": reason,
    })
    save_state(state)
    log_event("block", session=session_id, tokens=tokens, reason=reason, handoff=str(handoff))
    emit({"decision": "block",
          "reason": build_reason(tokens, threshold, handoff, session_id, memory_dir_for(transcript) is not None, request)})
    return 0


# --------------------------------------------------------------------------- SessionStart hook


def describe_age(path: Path) -> str:
    try:
        delta = time.time() - path.stat().st_mtime
    except OSError:
        return "unknown age"
    minutes = int(delta // 60)
    if minutes < 60:
        return f"{minutes} min ago"
    if minutes < 48 * 60:
        return f"{minutes // 60} h ago"
    return f"{minutes // (24 * 60)} d ago"


def run_session_start(payload: Dict[str, Any]) -> int:
    handoff = handoff_path_for(payload.get("transcript_path"), payload.get("cwd"))
    if not handoff.is_file():
        return 0
    print(f"rollover hand-off pending: read {handoff} first (written {describe_age(handoff)}).")
    return 0


# --------------------------------------------------------------------------- request / status


def _flag_value(argv: List[str], flag: str) -> Optional[str]:
    if flag in argv:
        idx = argv.index(flag)
        if idx + 1 < len(argv):
            return argv[idx + 1]
    return None


def _session_from(argv: List[str]) -> Optional[str]:
    return _flag_value(argv, "--session") or os.environ.get(ENV_SESSION)


def run_request(argv: List[str]) -> int:
    session_id = _session_from(argv)
    if not session_id:
        print("no session: run this inside a Claude Code session or pass --session <id>")
        return 2
    reason = ""
    if "--reason" in argv:
        idx = argv.index("--reason")
        reason = " ".join(argv[idx + 1:])
    path = write_request(session_id, reason)
    log_event("request", session=session_id, reason=reason)
    print(f"rollover requested for session {session_id}; it happens when this turn ends ({path}).")
    return 0


def newest_transcript(project_dir: Path) -> Optional[Path]:
    candidates = [p for p in project_dir.glob("*.jsonl") if p.is_file()]
    return max(candidates, key=lambda p: p.stat().st_mtime) if candidates else None


def _transcript_for_session(session_id: str) -> Optional[Path]:
    projects = Path.home() / ".claude" / "projects"
    if not projects.is_dir():
        return None
    hits = list(projects.glob(f"*/{_safe_name(session_id)}.jsonl"))
    return hits[0] if hits else None


def run_status(argv: List[str]) -> int:
    positional = [a for a in argv if not a.startswith("--")]
    transcript: Optional[Path] = None
    if positional:
        transcript = Path(positional[0])
        if transcript.is_dir():
            transcript = newest_transcript(transcript)
    else:
        session = _session_from(argv)
        if session:
            transcript = _transcript_for_session(session)
    if transcript is None or not transcript.is_file():
        print("usage: reverify rollover status <transcript.jsonl | project dir> (or run it inside a session)")
        return 2
    session_id = transcript.stem
    threshold = threshold_tokens()
    tokens = context_tokens(transcript)
    state = load_state(session_id, threshold)
    handoff = handoff_path_for(transcript)
    print(f"transcript : {transcript}")
    print(f"context    : {tokens if tokens is not None else 'unknown'} tokens")
    print(f"threshold  : {threshold} (step {step_tokens()}; 0 disables)")
    print(f"guard      : next fire at {state.get('next_trigger')} · pending={state.get('pending')} · "
          f"blocks={state.get('blocks')} · rollovers={state.get('rollovers')} · last={state.get('last_outcome')}")
    print(f"request    : {'pending' if request_path(session_id).is_file() else 'none'}")
    print(f"hand-off   : {handoff} · {('present, ' + describe_age(handoff)) if handoff.is_file() else 'absent'}")
    return 0


# --------------------------------------------------------------------------- install / uninstall


def hook_command(action: str) -> str:
    python = Path(sys.executable).resolve().as_posix()
    module = Path(__file__).resolve().as_posix()
    return f'"{python}" "{module}" {action}'


def hook_entries() -> Dict[str, Dict[str, Any]]:
    return {
        "Stop": {"hooks": [{"type": "command", "command": hook_command("stop"), "timeout": 20,
                            "statusMessage": "reverify rollover guard"}]},
        "SessionStart": {"hooks": [{"type": "command", "command": hook_command("session-start"), "timeout": 10}]},
    }


def _is_ours(entry: Dict[str, Any]) -> bool:
    return any(any(marker in str(h.get("command", "")) for marker in HOOK_MARKERS)
               for h in entry.get("hooks", []) if isinstance(h, dict))


def _backup(path: Path) -> Optional[Path]:
    if not path.is_file():
        return None
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = path.with_name(f"{path.name}.bak-reverify-{stamp}")
    shutil.copy2(path, backup)
    return backup


def install_settings(settings: Dict[str, Any], threshold: Optional[str] = None, step: Optional[str] = None,
                     disable_autocompact: bool = True) -> Dict[str, Any]:
    """Pure transform of a settings dict (tested without touching disk)."""
    if disable_autocompact:
        settings["autoCompactEnabled"] = False
        settings.pop("autoCompactWindow", None)
        settings.pop("precomputeCompactionEnabled", None)
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        hooks = {}
    for event, entry in hook_entries().items():
        existing = [e for e in hooks.get(event, []) if isinstance(e, dict) and not _is_ours(e)]
        existing.append(entry)
        hooks[event] = existing
    settings["hooks"] = hooks
    env = settings.get("env")
    if not isinstance(env, dict):
        env = {}
    if threshold is not None:
        env[ENV_TOKENS] = str(parse_tokens(threshold, DEFAULT_THRESHOLD))
    if step is not None:
        env[ENV_STEP] = str(parse_tokens(step, DEFAULT_STEP))
    if env:
        settings["env"] = env
    return settings


def uninstall_settings(settings: Dict[str, Any]) -> Dict[str, Any]:
    hooks = settings.get("hooks")
    if isinstance(hooks, dict):
        for event in list(hooks):
            kept = [e for e in hooks[event] if isinstance(e, dict) and not _is_ours(e)]
            if kept:
                hooks[event] = kept
            else:
                hooks.pop(event)
        if not hooks:
            settings.pop("hooks")
    if settings.get("autoCompactEnabled") is False:
        settings.pop("autoCompactEnabled")
    env = settings.get("env")
    if isinstance(env, dict):
        env.pop(ENV_TOKENS, None)
        env.pop(ENV_STEP, None)
        if not env:
            settings.pop("env")
    return settings


def _load_settings(path: Path) -> Dict[str, Any]:
    if not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} is not a JSON object")
    return data


def _save_settings(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def run_install(argv: List[str]) -> int:
    path = settings_path()
    data = _load_settings(path)
    backup = _backup(path)
    install_settings(data, threshold=_flag_value(argv, "--threshold"), step=_flag_value(argv, "--step"),
                     disable_autocompact="--keep-autocompact" not in argv)
    _save_settings(path, data)
    env = data.get("env") or {}
    print(f"installed into {path}")
    if backup:
        print(f"backup: {backup}")
    print(f"Stop hook          : {hook_command('stop')}")
    print(f"SessionStart hook  : {hook_command('session-start')}")
    print(f"autoCompactEnabled : {data.get('autoCompactEnabled', True)}")
    print(f"threshold          : {env.get(ENV_TOKENS) or DEFAULT_THRESHOLD} tokens (step {env.get(ENV_STEP) or DEFAULT_STEP})")
    print("new sessions pick this up; sessions already running keep their old settings.")
    return 0


def run_uninstall(argv: List[str]) -> int:
    path = settings_path()
    data = _load_settings(path)
    backup = _backup(path)
    uninstall_settings(data)
    _save_settings(path, data)
    print(f"removed from {path}" + (f" (backup: {backup})" if backup else ""))
    return 0


# --------------------------------------------------------------------------- launcher


def resolve_claude() -> str:
    """Prefer the native binary over the npm shim so the session is a single process."""
    found = shutil.which("claude")
    if found:
        candidate = Path(found).resolve().parent / "node_modules" / "@anthropic-ai" / "claude-code" / "bin" / "claude.exe"
        if os.name == "nt" and candidate.is_file():
            return str(candidate)
        return found
    raise FileNotFoundError("claude is not on PATH")


def opening_prompt(receipt: Dict[str, Any]) -> str:
    lines = [
        "[rollover] This is a fresh session that continues the previous one; the old context was dropped, not summarized.",
        f"Read the hand-off first: {receipt.get('handoff_path')} — then pull details on demand from the memory index it "
        "points to (and `reverify ledger --context` for verified facts).",
    ]
    first = receipt.get("first_user_message")
    last = receipt.get("last_user_message")
    if first:
        lines.append("The user's original request, verbatim: «" + str(first) + "»")
    if last and last != first:
        lines.append("The user's latest message, verbatim: «" + str(last) + "»")
    lines.append(
        "Continue from the hand-off's 'Next step'. If that step needs a decision from the user, say in one line what "
        "you need and wait. Do not mention context, cleanup, or this hand-off mechanism."
    )
    return "\n".join(lines)


def reset_console() -> None:
    try:
        if not sys.stdout.isatty():
            return
        sys.stdout.write("\x1b[?1049l\x1b[?25h\x1b[0m\r\n")
        sys.stdout.flush()
        if os.name != "nt":
            subprocess.run(["stty", "sane"], check=False)
    except Exception:  # pragma: no cover - cosmetic
        pass


def terminate(proc: "subprocess.Popen[Any]", graceful: bool = True, grace: float = 6.0) -> None:
    """Ask Claude Code to exit (two Ctrl-C at an idle prompt), then force it."""
    if proc.poll() is not None:
        return
    if graceful:
        try:
            if os.name == "nt":
                import ctypes

                kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
                for _ in range(2):
                    kernel32.GenerateConsoleCtrlEvent(0, 0)
                    time.sleep(0.4)
            else:
                for _ in range(2):
                    os.kill(proc.pid, signal.SIGINT)
                    time.sleep(0.4)
            try:
                proc.wait(timeout=grace)
                return
            except subprocess.TimeoutExpired:
                pass
        except Exception as exc:  # pragma: no cover - platform quirks
            debug(f"graceful exit failed: {exc!r}")
    if proc.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        proc.terminate()
    try:
        proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=grace)


class Launcher:
    """Run Claude Code; on a rollover receipt end the session and start a fresh one.

    Invariants (each has a test):
    - a receipt is consumed exactly once (atomic rename) and never re-used after a restart;
    - a user message that lands after the hand-off cancels that rollover;
    - a receipt with an unknown schema, or one arriving sooner than ``min_interval`` after
      the previous rollover, is ignored (fail closed);
    - the successor's first message quotes the user's original request verbatim.
    """

    def __init__(self, claude_args: List[str], exe: Optional[str] = None, poll: float = 0.5,
                 settle: float = 2.0, graceful: bool = True, max_rollovers: Optional[int] = None,
                 min_interval: float = DEFAULT_MIN_INTERVAL, quiet: bool = False):
        self.claude_args = list(claude_args)
        self.exe = exe
        self.poll = poll
        self.settle = settle
        self.graceful = graceful
        self.max_rollovers = max_rollovers
        self.min_interval = min_interval
        self.quiet = quiet
        self.rollovers: List[Dict[str, Any]] = []
        self.launches: List[List[str]] = []
        self.skipped: List[str] = []
        self._last_rollover_at: Optional[float] = None

    def _say(self, text: str) -> None:
        if not self.quiet:
            print(f"[reverify rollover] {text}", file=sys.stderr, flush=True)

    def spawn(self, opening: Optional[str]) -> Tuple[str, "subprocess.Popen[Any]"]:
        launch_id = uuid.uuid4().hex
        env = dict(os.environ)
        env[ENV_LAUNCH_ID] = launch_id
        cmd = [self.exe or resolve_claude()] + self.claude_args + ([opening] if opening else [])
        self.launches.append(cmd)
        log_event("launch", launch_id=launch_id, rollovers=len(self.rollovers))
        return launch_id, subprocess.Popen(cmd, env=env)

    def _discard(self, path: Path, why: str) -> None:
        self.skipped.append(why)
        self._say(why)
        log_event("skipped", why=why, receipt=str(path))
        try:
            path.unlink()
        except OSError:
            pass

    def wait_for_receipt(self, launch_id: str, proc: "subprocess.Popen[Any]") -> Optional[Dict[str, Any]]:
        path = receipt_path(launch_id)
        while proc.poll() is None:
            receipt = _read_json(path) if path.is_file() else None
            if receipt is None:
                time.sleep(self.poll)
                continue
            if receipt.get("schema") != RECEIPT_SCHEMA:
                self._discard(path, f"receipt schema {receipt.get('schema')!r} is not {RECEIPT_SCHEMA}; ignored")
                continue
            if self._last_rollover_at is not None and time.time() - self._last_rollover_at < self.min_interval:
                self._discard(path, "rollover requested too soon after the previous one; ignored")
                continue
            # Fence: give a queued user message the chance to land; if one did, this rollover is off.
            time.sleep(self.settle)
            if proc.poll() is not None:
                break
            if user_message_after(receipt.get("transcript_path"), float(receipt.get("written_epoch") or 0.0)):
                self._discard(path, "a user message arrived after the hand-off; this rollover is off")
                continue
            try:
                os.replace(path, path.with_suffix(".consumed.json"))
            except OSError:
                pass
            return receipt
        return None

    def run(self) -> int:
        self._say("auto-rollover on; built-in compaction stays off")
        previous = signal.getsignal(signal.SIGINT)
        try:
            signal.signal(signal.SIGINT, signal.SIG_IGN)
        except (ValueError, OSError):  # not the main thread / unsupported
            pass
        opening: Optional[str] = None
        try:
            while True:
                launch_id, proc = self.spawn(opening)
                receipt = self.wait_for_receipt(launch_id, proc)
                if receipt is None:
                    return proc.returncode if proc.returncode is not None else 0
                terminate(proc, graceful=self.graceful)
                self.rollovers.append(receipt)
                self._last_rollover_at = time.time()
                log_event("rollover", launch_id=launch_id, session=receipt.get("session_id"),
                          tokens=receipt.get("context_tokens"), transcript_sha256=receipt.get("transcript_sha256"))
                reset_console()
                self._say(f"rollover #{len(self.rollovers)} at {fmt_k(receipt.get('context_tokens'))}; fresh session")
                opening = opening_prompt(receipt)
                if self.max_rollovers is not None and len(self.rollovers) >= self.max_rollovers:
                    return 0
        finally:
            try:
                signal.signal(signal.SIGINT, previous)
            except (ValueError, OSError):
                pass


LAUNCHER_FLAGS_WITH_VALUE = ("--claude", "--poll", "--settle", "--max-rollovers", "--min-interval")
LAUNCHER_FLAGS = ("--force-kill", "--quiet")


def split_launcher_args(argv: List[str]) -> Tuple[List[str], List[str]]:
    """Launcher options vs. arguments passed through to Claude Code.

    ``--`` separates the two explicitly; without it, only the launcher's own flags are
    taken and everything else goes to Claude Code (so ``reverify rollover run
    --permission-mode auto`` works as expected).
    """
    if "--" in argv:
        idx = argv.index("--")
        return argv[:idx], argv[idx + 1:]
    own: List[str] = []
    passthrough: List[str] = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in LAUNCHER_FLAGS_WITH_VALUE and i + 1 < len(argv):
            own.extend(argv[i:i + 2])
            i += 2
            continue
        if arg in LAUNCHER_FLAGS:
            own.append(arg)
        else:
            passthrough.append(arg)
        i += 1
    return own, passthrough


def run_launcher(argv: List[str]) -> int:
    own, passthrough = split_launcher_args(list(argv))
    max_rollovers = _flag_value(own, "--max-rollovers")
    launcher = Launcher(
        passthrough,
        exe=_flag_value(own, "--claude"),
        poll=float(_flag_value(own, "--poll") or 0.5),
        settle=float(_flag_value(own, "--settle") or 2.0),
        graceful="--force-kill" not in own,
        max_rollovers=int(max_rollovers) if max_rollovers else None,
        min_interval=float(_flag_value(own, "--min-interval") or DEFAULT_MIN_INTERVAL),
        quiet="--quiet" in own,
    )
    return launcher.run()


# --------------------------------------------------------------------------- entry point

USAGE = """reverify rollover <action> [options]

  install [--threshold 200k] [--step 100k] [--keep-autocompact]
                       write the Stop + SessionStart hooks into ~/.claude/settings.json and turn built-in
                       auto-compaction off (backup kept next to the file)
  uninstall            remove the hooks, restore auto-compaction
  run [--max-rollovers N] [--settle S] [--min-interval S] [--force-kill] [--quiet] -- <claude args>
                       start Claude Code and replace the session with a fresh one on every receipt
  request [--reason ...]
                       (run by the model, inside a session) roll over at the end of this turn
  status [<transcript.jsonl | project dir>]
                       tokens, threshold, guard state, hand-off
  stop / session-start hook entry points (read the hook JSON on stdin)
"""


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    configure_streams()
    action = argv[0] if argv else "help"
    rest = argv[1:]
    try:
        if action == "stop":
            return run_stop(read_hook_input())
        if action == "session-start":
            return run_session_start(read_hook_input())
    except Exception as exc:  # hooks fail open, always
        debug(f"error: {exc!r}")
        return 0
    if action == "request":
        return run_request(rest)
    if action == "status":
        return run_status(rest)
    if action == "install":
        return run_install(rest)
    if action == "uninstall":
        return run_uninstall(rest)
    if action == "run":
        return run_launcher(rest)
    print(USAGE)
    return 0 if action in ("help", "-h", "--help") else 2


if __name__ == "__main__":
    sys.exit(main())
