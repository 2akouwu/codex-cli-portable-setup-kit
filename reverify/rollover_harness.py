#!/usr/bin/env python3
"""Rollover for any agent CLI: hand off to files, receipt, fresh session - never a summary.

Claude Code, Codex CLI, Gemini CLI and OpenCode all deal with a full context window the same
way: the model summarizes the transcript and keeps going, so whatever it believed - including
its own mistakes - travels forward as if it were state. This module applies the reverify rule
to all four instead: **state lives in files, the conversation is a cache**. One state machine,
one hand-off contract, one launcher; per-harness adapters cover the three things that differ
(how hooks are wired, where the transcript lives, how a fresh session is started).

The contract (identical everywhere):

1. **Guard.** At the harness's "agent finished a turn" hook the guard measures the live
   context from the transcript. At the threshold - or when the model itself asked with
   ``reverify rollover request`` - it blocks that stop once and asks the model to write the
   hand-off *file* (fixed sections, labelled UNVERIFIED) and its memory index.
2. **Receipt, fail closed.** On the next stop the guard checks that the file was really
   rewritten and is well-formed; only then does it write a receipt carrying the transcript's
   SHA-256 and the user's verbatim first and latest messages. Otherwise nothing happens and
   the guard re-arms further up.
3. **Fresh session.** Whoever can end the session does: the launcher (``reverify rollover
   run --harness X -- <args>``) for any CLI; Gemini's own ``clearContext`` in-process; an
   OpenCode plugin through the SDK. The successor opens on the hand-off file and the user's
   original request quoted verbatim, so objective A cannot drift into B.

Adapters: ``claude`` (Stop / SessionStart hooks, transcript JSONL), ``codex`` (same hook
shape, ``hooks.json`` + ``[features] hooks``, rollout JSONL), ``gemini`` (AfterAgent deny +
clearContext, BeforeAgent injection, chats JSONL), ``opencode`` (plugin on ``session.idle``,
SDK prompt / new session, SQLite store for status).

Everything is stdlib; every hook path fails open (exit 0, silent); every rollover path fails
closed. Decisions are appended to ``<state dir>/events.jsonl``.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

RECEIPT_SCHEMA = 1
DEFAULT_THRESHOLD = 200_000
DEFAULT_STEP = 100_000
DEFAULT_MIN_INTERVAL = 120.0
HANDOFF_NAME = "rollover-handoff.md"
HANDOFF_MAX_BYTES = 24 * 1024
ANCHOR_MAX_CHARS = 1200
TAIL_BYTES = 4 * 1024 * 1024
HOOK_MARKERS = ("rollover_harness.py", "claude_rollover.py", "rollover_guard.py", "reverify-rollover")
HARNESSES = ("claude", "codex", "gemini", "opencode")
CODEX_NO_COMPACT_LIMIT = 100_000_000

ENV_TOKENS = "REVERIFY_ROLLOVER_TOKENS"
ENV_STEP = "REVERIFY_ROLLOVER_STEP"
ENV_STATE_DIR = "REVERIFY_ROLLOVER_STATE_DIR"
ENV_SETTINGS = "REVERIFY_ROLLOVER_SETTINGS"
ENV_HOME = "REVERIFY_ROLLOVER_HOME"
ENV_LAUNCH_ID = "REVERIFY_ROLLOVER_LAUNCH_ID"
ENV_DEBUG = "REVERIFY_ROLLOVER_DEBUG"
ENV_SESSION = "CLAUDE_CODE_SESSION_ID"
SESSION_ENV_VARS = ("REVERIFY_ROLLOVER_SESSION", "CLAUDE_CODE_SESSION_ID", "CODEX_THREAD_ID", "GEMINI_SESSION_ID",
                    "OPENCODE_SESSION_ID")


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


def home_dir() -> Path:
    override = os.environ.get(ENV_HOME)
    return Path(override) if override else Path.home()


def state_dir() -> Path:
    override = os.environ.get(ENV_STATE_DIR)
    if override:
        return Path(override)
    return home_dir() / ".reverify" / "rollover"


def settings_path() -> Path:
    """Claude Code's settings file (kept as the historical name of this helper)."""
    override = os.environ.get(ENV_SETTINGS)
    if override:
        return Path(override)
    return home_dir() / ".claude" / "settings.json"


def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(text: str) -> Optional[float]:
    """ISO-8601 (with Z or offset) -> epoch seconds; None when unparsable."""
    if not text:
        return None
    try:
        value = str(text).strip()
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


def _clean_text(text: str) -> Optional[str]:
    """A real user utterance: non-empty and not an injected <tag> block."""
    text = (text or "").strip()
    if not text or text.startswith("<"):
        return None
    return text


def _tail_lines(path: Path) -> List[bytes]:
    size = path.stat().st_size
    with path.open("rb") as handle:
        if size > TAIL_BYTES:
            handle.seek(size - TAIL_BYTES)
            return handle.read().split(b"\n")[1:]
        return handle.read().split(b"\n")


def _records(lines: Iterable[bytes], needle: bytes, reverse: bool = True):
    ordered = reversed(list(lines)) if reverse else lines
    for line in ordered:
        if needle not in line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict):
            yield record


def _sha256_file(path: Path) -> Tuple[Optional[str], Optional[int]]:
    try:
        data = path.read_bytes()
    except OSError:
        return None, None
    return hashlib.sha256(data).hexdigest(), len(data)


# --------------------------------------------------------------------------- transcripts: Claude Code


def _usage_tokens(usage: Dict[str, Any]) -> int:
    total = 0
    for key in ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens", "output_tokens"):
        value = usage.get(key)
        if isinstance(value, (int, float)):
            total += int(value)
    return total


def context_tokens(transcript_path: Any) -> Optional[int]:
    """Claude Code: the last assistant usage of the main conversation."""
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
    """Claude Code: the text of a real user message; None for tool results, meta and command echoes."""
    if record.get("type") != "user" or record.get("isSidechain") is True or record.get("isMeta") is True:
        return None
    if record.get("toolUseResult") is not None:
        return None
    message = record.get("message")
    if not isinstance(message, dict):
        return None
    content = message.get("content")
    if isinstance(content, str):
        return _clean_text(content)
    if isinstance(content, list):
        if any(isinstance(b, dict) and b.get("type") == "tool_result" for b in content):
            return None
        parts = [b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text"]
        return _clean_text("\n".join(p for p in parts if isinstance(p, str)))
    return None


def user_message_after(transcript_path: Any, since_epoch: float) -> bool:
    """Claude Code: a real user message landed after ``since_epoch``."""
    return _message_after(transcript_path, since_epoch, b'"user"', _human_text, "timestamp")


def _message_after(transcript_path: Any, since_epoch: float, needle: bytes, extract, stamp_key: str) -> bool:
    if not transcript_path:
        return False
    path = Path(transcript_path)
    if not path.is_file():
        return False
    for record in _records(_tail_lines(path), needle):
        stamp = parse_iso(str(record.get(stamp_key, "")))
        if stamp is None:
            continue
        if stamp < since_epoch:
            break
        if extract(record) is not None:
            return True
    return False


def _anchors_from(path: Path, needle: bytes, extract) -> Dict[str, Any]:
    result: Dict[str, Any] = {"first_user_message": None, "last_user_message": None,
                              "transcript_sha256": None, "transcript_bytes": None}
    if not path.is_file():
        return result
    result["transcript_sha256"], result["transcript_bytes"] = _sha256_file(path)
    lines = path.read_bytes().split(b"\n")
    for record in _records(lines, needle, reverse=False):
        text = extract(record)
        if text is not None:
            result["first_user_message"] = text[:ANCHOR_MAX_CHARS]
            break
    for record in _records(lines, needle):
        text = extract(record)
        if text is not None:
            result["last_user_message"] = text[:ANCHOR_MAX_CHARS]
            break
    return result


def transcript_anchors(transcript_path: Any) -> Dict[str, Any]:
    """Claude Code: verbatim first / latest user messages plus a hash of the transcript now."""
    if not transcript_path:
        return _anchors_from(Path("/nonexistent"), b"", _human_text)
    return _anchors_from(Path(transcript_path), b'"user"', _human_text)


# --------------------------------------------------------------------------- transcripts: Codex CLI


def codex_sessions_dir() -> Path:
    return home_dir() / ".codex" / "sessions"


def codex_find_rollout(session_id: str) -> Optional[Path]:
    """Codex hands ``transcript_path`` as null in some builds; find the rollout by session id."""
    root = codex_sessions_dir()
    if not session_id or not root.is_dir():
        return None
    hits = sorted(root.glob(f"*/*/*/rollout-*{session_id}*.jsonl"), key=lambda p: p.stat().st_mtime)
    return hits[-1] if hits else None


def codex_context_tokens(transcript_path: Any) -> Optional[int]:
    """Codex rollout: the last ``token_count`` event's ``last_token_usage``."""
    if not transcript_path:
        return None
    path = Path(transcript_path)
    if not path.is_file():
        return None
    for record in _records(_tail_lines(path), b"token_count"):
        payload = record.get("payload")
        if not isinstance(payload, dict) or payload.get("type") != "token_count":
            continue
        info = payload.get("info")
        if not isinstance(info, dict):
            continue
        usage = info.get("last_token_usage") or info.get("total_token_usage")
        if not isinstance(usage, dict):
            continue
        total = usage.get("total_tokens")
        if isinstance(total, (int, float)) and total > 0:
            return int(total)
        tokens = int(usage.get("input_tokens") or 0) + int(usage.get("output_tokens") or 0)
        if tokens > 0:
            return tokens
    return None


def codex_context_window(transcript_path: Any) -> Optional[int]:
    """Codex rollout: ``model_context_window`` from the last ``token_count`` event."""
    if not transcript_path:
        return None
    path = Path(transcript_path)
    if not path.is_file():
        return None
    for record in _records(_tail_lines(path), b"token_count"):
        payload = record.get("payload")
        if not isinstance(payload, dict) or payload.get("type") != "token_count":
            continue
        info = payload.get("info")
        if isinstance(info, dict):
            window = info.get("model_context_window")
            if isinstance(window, (int, float)) and window > 0:
                return int(window)
    return None


def _codex_user_text(record: Dict[str, Any]) -> Optional[str]:
    payload = record.get("payload")
    if not isinstance(payload, dict):
        return None
    if record.get("type") == "response_item" and payload.get("type") == "message" and payload.get("role") == "user":
        parts = []
        for block in payload.get("content") or []:
            if isinstance(block, dict) and block.get("type") == "input_text" and isinstance(block.get("text"), str):
                parts.append(block["text"])
        return _clean_text("\n".join(parts))
    if record.get("type") == "event_msg" and payload.get("type") == "user_message":
        message = payload.get("message")
        return _clean_text(message) if isinstance(message, str) else None
    return None


def codex_user_message_after(transcript_path: Any, since_epoch: float) -> bool:
    return _message_after(transcript_path, since_epoch, b'"user"', _codex_user_text, "timestamp")


def codex_anchors(transcript_path: Any) -> Dict[str, Any]:
    return _anchors_from(Path(transcript_path) if transcript_path else Path("/nonexistent"), b'"user"', _codex_user_text)


# --------------------------------------------------------------------------- transcripts: Gemini CLI


def gemini_context_tokens(transcript_path: Any) -> Optional[int]:
    """Gemini chats JSONL: the last ``gemini`` message's ``tokens``."""
    if not transcript_path:
        return None
    path = Path(transcript_path)
    if not path.is_file():
        return None
    for record in _records(_tail_lines(path), b'"gemini"'):
        if record.get("type") != "gemini":
            continue
        tokens = record.get("tokens")
        if not isinstance(tokens, dict):
            continue
        total = tokens.get("total")
        if isinstance(total, (int, float)) and total > 0:
            return int(total)
        summed = sum(int(tokens.get(k) or 0) for k in ("input", "output", "thoughts", "tool"))
        if summed > 0:
            return summed
    return None


def _gemini_parts_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        return str(content.get("text") or "")
    if isinstance(content, list):
        return "\n".join(_gemini_parts_text(c) for c in content)
    return ""


def _gemini_user_text(record: Dict[str, Any]) -> Optional[str]:
    if record.get("type") != "user":
        return None
    return _clean_text(_gemini_parts_text(record.get("displayContent") or record.get("content")))


def gemini_user_message_after(transcript_path: Any, since_epoch: float) -> bool:
    return _message_after(transcript_path, since_epoch, b'"user"', _gemini_user_text, "timestamp")


def gemini_anchors(transcript_path: Any) -> Dict[str, Any]:
    return _anchors_from(Path(transcript_path) if transcript_path else Path("/nonexistent"), b'"user"', _gemini_user_text)


# --------------------------------------------------------------------------- transcripts: OpenCode (SQLite)


def opencode_db_path() -> Path:
    override = os.environ.get("OPENCODE_DB")
    if override:
        return Path(override)
    return home_dir() / ".local" / "share" / "opencode" / "opencode.db"


def opencode_session_stats(session_id: str, db_path: Optional[Path] = None) -> Dict[str, Any]:
    """Tokens of the last assistant message and the verbatim user anchors, read from the store."""
    result: Dict[str, Any] = {"tokens": None, "first_user_message": None, "last_user_message": None}
    path = db_path or opencode_db_path()
    if not session_id or not path.is_file():
        return result
    try:
        con = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    except sqlite3.Error:
        return result
    try:
        rows = con.execute("select id, data from message where session_id = ? order by time_created", (session_id,)).fetchall()
        user_ids: List[str] = []
        for message_id, data in rows:
            try:
                info = json.loads(data)
            except ValueError:
                continue
            if info.get("role") == "assistant" and isinstance(info.get("tokens"), dict):
                tokens = info["tokens"]
                total = tokens.get("total")
                if isinstance(total, (int, float)) and total > 0:
                    result["tokens"] = int(total)
                else:
                    cache = tokens.get("cache") if isinstance(tokens.get("cache"), dict) else {}
                    result["tokens"] = int(tokens.get("input") or 0) + int(tokens.get("output") or 0) + int(cache.get("read") or 0)
            elif info.get("role") == "user":
                user_ids.append(message_id)
        texts: List[str] = []
        for message_id in user_ids:
            parts = con.execute("select data from part where message_id = ? order by time_created", (message_id,)).fetchall()
            chunks = []
            for (pdata,) in parts:
                try:
                    part = json.loads(pdata)
                except ValueError:
                    continue
                if part.get("type") == "text" and isinstance(part.get("text"), str):
                    chunks.append(part["text"])
            text = _clean_text("\n".join(chunks))
            if text:
                texts.append(text)
        if texts:
            result["first_user_message"] = texts[0][:ANCHOR_MAX_CHARS]
            result["last_user_message"] = texts[-1][:ANCHOR_MAX_CHARS]
    except sqlite3.Error:
        pass
    finally:
        con.close()
    return result


# --------------------------------------------------------------------------- hand-off location & shape


def memory_dir_for(transcript_path: Any) -> Optional[Path]:
    """Claude Code keeps auto-memory next to the transcripts: <project dir>/memory."""
    if not transcript_path:
        return None
    candidate = Path(transcript_path).resolve().parent / "memory"
    return candidate if candidate.is_dir() else None


def handoff_path_for(transcript_path: Any, cwd: Any = None, harness: str = "claude") -> Path:
    if harness == "claude":
        memory_dir = memory_dir_for(transcript_path)
        if memory_dir is not None:
            return memory_dir / HANDOFF_NAME
    return Path(str(cwd) if cwd else ".").resolve() / ".reverify" / HANDOFF_NAME


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


def cwd_request_key(cwd: Any) -> str:
    resolved = Path(str(cwd) if cwd else ".").resolve().as_posix().lower()
    return "cwd-" + hashlib.sha1(resolved.encode("utf-8")).hexdigest()[:16]


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
        "opening_pending": None,
    }
    saved = _read_json(state_path(session_id))
    if saved:
        state.update(saved)
    return state


def save_state(state: Dict[str, Any]) -> None:
    _write_json(state_path(str(state.get("session_id", "unknown"))), state)


def write_request(key: str, reason: str) -> Path:
    path = request_path(key)
    _write_json(path, {"key": key, "reason": reason[:300], "requested_at": now_iso()})
    return path


def pop_request(session_id: str, cwd: Any = None) -> Optional[Dict[str, Any]]:
    for key in (session_id, cwd_request_key(cwd) if cwd else None):
        if not key:
            continue
        path = request_path(key)
        data = _read_json(path)
        if data is None:
            continue
        try:
            path.unlink()
        except OSError:
            pass
        return data
    return None


def write_receipt(session_id: str, transcript: Any, handoff: Path, tokens: Optional[int], reason: str,
                  launch_id: Optional[str], anchors: Optional[Dict[str, Any]] = None, harness: str = "claude") -> Path:
    receipt: Dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "harness": harness,
        "session_id": session_id,
        "launch_id": launch_id,
        "transcript_path": str(transcript) if transcript else None,
        "handoff_path": str(handoff),
        "context_tokens": tokens,
        "reason": reason,
        "written_at": now_iso(),
        "written_epoch": time.time(),
        "first_user_message": None,
        "last_user_message": None,
        "transcript_sha256": None,
        "transcript_bytes": None,
    }
    if anchors:
        receipt.update({k: v for k, v in anchors.items() if k in receipt})
    path = receipt_path(launch_id or session_id)
    _write_json(path, receipt)
    return path


# --------------------------------------------------------------------------- the hand-off text

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
        else "3. Put the file's path into whichever memory or notes index you maintain for this project (if any)."
    )
    template = HANDOFF_TEMPLATE.format(when=now_iso(), session=session_id, tokens=fmt_k(tokens))
    return (
        f"[reverify rollover] {why} Built-in compaction is off. Before this turn ends, hand off to files, "
        "then finish your reply as you normally would.\n"
        "Rule: state lives in files, the conversation is a cache. Do not restate or summarize in the conversation, "
        "and do not tell the user about context, quality, cleanup, or any /clear or /compact action.\n\n"
        "1. Write this milestone's conclusions into the relevant memory or notes file (update existing files; do not re-copy what is already there).\n"
        f"2. Overwrite the hand-off file `{handoff}` with exactly these sections, one page at most, nothing else:\n"
        + "\n".join("   " + line for line in template.splitlines())
        + f"\n{memory_line}\n"
        "4. If this session used reverify (ledger or re_checkpoint), call re_checkpoint save once with the same content.\n"
        "5. Then close with what you were going to tell the user, without mentioning any of the above."
    )


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


# --------------------------------------------------------------------------- the guard (harness-agnostic)


WINDOW_FRACTION = 0.75


def effective_threshold(threshold: int, window: Optional[int]) -> int:
    """Never let the configured threshold sit above the model's real window.

    Native compaction is off, so on a small-window model the guard is the only net: when
    the harness tells us the window, the threshold is capped at 75% of it.
    """
    if window and window > 0:
        return min(threshold, int(window * WINDOW_FRACTION))
    return threshold


def run_guard(harness: "Harness", session_id: str, transcript: Any, cwd: Any, tokens: Optional[int],
              anchors_fn, env: Optional[Dict[str, str]] = None, window: Optional[int] = None) -> Dict[str, Any]:
    """One step of the state machine. Returns {"action": "allow"|"block"|"receipt", ...}."""
    env = os.environ if env is None else env
    threshold = threshold_tokens()
    if threshold <= 0:
        return {"action": "allow", "why": "disabled"}
    threshold = effective_threshold(threshold, window)
    state = load_state(session_id, threshold)
    step = step_tokens()
    if window and window > 0:
        state["context_window"] = int(window)
        step = max(5_000, min(step, int(window * 0.1)))   # small window: refresh the hand-off more often
    request = pop_request(session_id, cwd)

    if state.get("pending"):
        handoff = Path(str(state.get("handoff_path") or handoff_path_for(transcript, cwd, harness.name)))
        problem = validate_handoff(handoff, float(state.get("blocked_epoch") or 0.0))
        base = state.get("blocked_tokens") or tokens or 0
        state["pending"] = False
        state["next_trigger"] = max(int(base), tokens or 0) + step
        state["released_at"] = now_iso()
        if problem is None:
            launch_id = env.get(ENV_LAUNCH_ID)
            receipt_file = write_receipt(session_id, transcript, handoff, tokens, str(state.get("trigger_reason") or "threshold"),
                                         launch_id, anchors_fn(), harness.name)
            receipt = _read_json(receipt_file) or {}
            state["rollovers"] = int(state.get("rollovers", 0)) + 1
            state["last_outcome"] = "receipt"
            state["last_receipt"] = str(receipt_file)
            inline = harness.inline_reset and not launch_id
            if inline:
                state["opening_pending"] = opening_prompt(receipt)
            save_state(state)
            log_event("receipt", harness=harness.name, session=session_id, tokens=tokens, receipt=str(receipt_file),
                      handoff=str(handoff), launch_id=launch_id, inline=inline)
            return {"action": "receipt", "receipt": receipt, "inline": inline, "opening": opening_prompt(receipt)}
        state["last_outcome"] = "handoff_rejected: " + problem
        save_state(state)
        log_event("handoff_rejected", harness=harness.name, session=session_id, tokens=tokens, problem=problem, handoff=str(handoff))
        return {"action": "allow", "why": problem}

    if request is None and (tokens is None or tokens < int(state.get("next_trigger", threshold))):
        return {"action": "allow", "why": f"{tokens} < {state.get('next_trigger')}"}

    handoff = handoff_path_for(transcript, cwd, harness.name)
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
    log_event("block", harness=harness.name, session=session_id, tokens=tokens, reason=reason, handoff=str(handoff))
    text = build_reason(tokens, threshold, handoff, session_id,
                        harness.name == "claude" and memory_dir_for(transcript) is not None, request)
    return {"action": "block", "text": text}


# --------------------------------------------------------------------------- harness adapters


class Harness:
    name = "base"
    exe = ""
    inline_reset = False            # can the harness drop its own context in-process?
    stop_event = "Stop"
    start_event = "SessionStart"

    # -- payload / transcript ------------------------------------------------
    def parse_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        session_id = str(payload.get("session_id") or _session_from_env() or "unknown")
        return {"session_id": session_id, "transcript": payload.get("transcript_path"), "cwd": payload.get("cwd"),
                "stop_hook_active": bool(payload.get("stop_hook_active"))}

    def context_tokens(self, transcript: Any, session_id: str) -> Optional[int]:
        return context_tokens(transcript)

    def context_window(self, transcript: Any, session_id: str) -> Optional[int]:
        """The model's context window when the harness records it; None otherwise."""
        return None

    def anchors(self, transcript: Any, session_id: str) -> Dict[str, Any]:
        return transcript_anchors(transcript)

    def user_message_after(self, transcript: Any, since: float) -> bool:
        return user_message_after(transcript, since)

    # -- hook output ------------------------------------------------------------
    def format_block(self, text: str) -> Dict[str, Any]:
        return {"decision": "block", "reason": text}

    def format_receipt(self, result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        return None

    def format_context(self, text: str, event: str) -> Optional[Dict[str, Any]]:
        """None means: print the text as plain stdout (Claude / Codex add it as context)."""
        return None

    # -- launching --------------------------------------------------------------
    def launch_args(self, args: List[str], opening: Optional[str]) -> List[str]:
        return list(args) + ([opening] if opening else [])

    def resolve_exe(self) -> str:
        found = shutil.which(self.exe)
        if not found:
            raise FileNotFoundError(f"{self.exe} is not on PATH")
        return found

    # -- install ----------------------------------------------------------------
    def hook_command(self, event: str) -> str:
        python = Path(sys.executable).resolve().as_posix()
        module = Path(__file__).resolve().as_posix()
        return f'"{python}" "{module}" hook {self.name} {event}'

    def install(self, threshold: Optional[str], step: Optional[str], disable_autocompact: bool) -> List[str]:
        raise NotImplementedError

    def uninstall(self) -> List[str]:
        raise NotImplementedError


def _session_from_env() -> Optional[str]:
    for key in SESSION_ENV_VARS:
        value = os.environ.get(key)
        if value:
            return value
    return None


def _backup(path: Path) -> Optional[Path]:
    if not path.is_file():
        return None
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = path.with_name(f"{path.name}.bak-reverify-{stamp}")
    shutil.copy2(path, backup)
    return backup


def _is_ours(entry: Dict[str, Any]) -> bool:
    return any(any(marker in str(h.get("command", "")) for marker in HOOK_MARKERS)
               for h in entry.get("hooks", []) if isinstance(h, dict))


def _load_json_file(path: Path) -> Dict[str, Any]:
    if not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} is not a JSON object")
    return data


def _save_json_file(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _merge_hooks(hooks: Any, entries: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    hooks = hooks if isinstance(hooks, dict) else {}
    for event, entry in entries.items():
        existing = [e for e in hooks.get(event, []) if isinstance(e, dict) and not _is_ours(e)]
        existing.append(entry)
        hooks[event] = existing
    return hooks


def _strip_hooks(hooks: Any) -> Any:
    if not isinstance(hooks, dict):
        return hooks
    for event in list(hooks):
        kept = [e for e in hooks[event] if isinstance(e, dict) and not _is_ours(e)]
        if kept:
            hooks[event] = kept
        else:
            hooks.pop(event)
    return hooks


def _apply_env(settings: Dict[str, Any], threshold: Optional[str], step: Optional[str]) -> None:
    env = settings.get("env")
    if not isinstance(env, dict):
        env = {}
    if threshold is not None:
        env[ENV_TOKENS] = str(parse_tokens(threshold, DEFAULT_THRESHOLD))
    if step is not None:
        env[ENV_STEP] = str(parse_tokens(step, DEFAULT_STEP))
    if env:
        settings["env"] = env


def _strip_env(settings: Dict[str, Any]) -> None:
    env = settings.get("env")
    if isinstance(env, dict):
        env.pop(ENV_TOKENS, None)
        env.pop(ENV_STEP, None)
        if not env:
            settings.pop("env")


# ---- Claude Code ----------------------------------------------------------------


class ClaudeHarness(Harness):
    name = "claude"
    exe = "claude"

    def hook_entries(self) -> Dict[str, Dict[str, Any]]:
        return {
            "Stop": {"hooks": [{"type": "command", "command": self.hook_command("stop"), "timeout": 20,
                                "statusMessage": "reverify rollover guard"}]},
            "SessionStart": {"hooks": [{"type": "command", "command": self.hook_command("session-start"), "timeout": 10}]},
        }

    def resolve_exe(self) -> str:
        found = shutil.which("claude")
        if found:
            candidate = Path(found).resolve().parent / "node_modules" / "@anthropic-ai" / "claude-code" / "bin" / "claude.exe"
            if os.name == "nt" and candidate.is_file():
                return str(candidate)
            return found
        raise FileNotFoundError("claude is not on PATH")

    def apply_settings(self, settings: Dict[str, Any], threshold: Optional[str], step: Optional[str],
                       disable_autocompact: bool) -> Dict[str, Any]:
        if disable_autocompact:
            settings["autoCompactEnabled"] = False
            settings.pop("autoCompactWindow", None)
            settings.pop("precomputeCompactionEnabled", None)
        settings["hooks"] = _merge_hooks(settings.get("hooks"), self.hook_entries())
        _apply_env(settings, threshold, step)
        return settings

    def strip_settings(self, settings: Dict[str, Any]) -> Dict[str, Any]:
        hooks = _strip_hooks(settings.get("hooks"))
        if isinstance(hooks, dict) and not hooks:
            settings.pop("hooks", None)
        if settings.get("autoCompactEnabled") is False:
            settings.pop("autoCompactEnabled")
        _strip_env(settings)
        return settings

    def install(self, threshold, step, disable_autocompact):
        path = settings_path()
        data = _load_json_file(path)
        backup = _backup(path)
        self.apply_settings(data, threshold, step, disable_autocompact)
        _save_json_file(path, data)
        return [f"claude: hooks Stop + SessionStart in {path}" + (f" (backup {backup.name})" if backup else ""),
                f"claude: autoCompactEnabled = {data.get('autoCompactEnabled', True)}"]

    def uninstall(self):
        path = settings_path()
        data = _load_json_file(path)
        backup = _backup(path)
        self.strip_settings(data)
        _save_json_file(path, data)
        return [f"claude: hooks removed from {path}" + (f" (backup {backup.name})" if backup else "")]


# ---- Codex CLI --------------------------------------------------------------------


class CodexHarness(Harness):
    name = "codex"
    exe = "codex"

    def parse_payload(self, payload):
        fields = super().parse_payload(payload)
        if not fields["transcript"]:
            found = codex_find_rollout(fields["session_id"])
            fields["transcript"] = str(found) if found else None
        return fields

    def context_tokens(self, transcript, session_id):
        return codex_context_tokens(transcript)

    def context_window(self, transcript, session_id):
        return codex_context_window(transcript)

    def anchors(self, transcript, session_id):
        return codex_anchors(transcript)

    def user_message_after(self, transcript, since):
        return codex_user_message_after(transcript, since)

    def hook_entries(self) -> Dict[str, Dict[str, Any]]:
        return {
            "Stop": {"hooks": [{"type": "command", "command": self.hook_command("stop"), "timeout": 20,
                                "statusMessage": "reverify rollover guard"}]},
            "SessionStart": {"hooks": [{"type": "command", "command": self.hook_command("session-start"), "timeout": 10}]},
        }

    @staticmethod
    def hooks_path() -> Path:
        return home_dir() / ".codex" / "hooks.json"

    @staticmethod
    def config_path() -> Path:
        return home_dir() / ".codex" / "config.toml"

    @staticmethod
    def apply_config_toml(text: str, disable_autocompact: bool) -> str:
        """Set [features] hooks = true and (optionally) a compaction limit no session reaches."""
        lines = text.splitlines()
        # top-level keys must precede the first table
        first_table = next((i for i, line in enumerate(lines) if re.match(r"^\s*\[", line)), len(lines))
        if disable_autocompact:
            pattern = re.compile(r"^\s*model_auto_compact_token_limit\s*=")
            idx = next((i for i, line in enumerate(lines[:first_table]) if pattern.match(line)), None)
            entry = f"model_auto_compact_token_limit = {CODEX_NO_COMPACT_LIMIT}  # reverify rollover: hand off instead of compacting"
            if idx is None:
                insert_at = first_table
                while insert_at > 0 and not lines[insert_at - 1].strip():
                    insert_at -= 1          # keep it with the other top-level keys, above the blank line
                lines.insert(insert_at, entry)
                first_table += 1
            else:
                lines[idx] = entry
        # [features] hooks = true
        feat = next((i for i, line in enumerate(lines) if re.match(r"^\s*\[features\]\s*$", line)), None)
        if feat is None:
            if lines and lines[-1].strip():
                lines.append("")
            lines.extend(["[features]", "hooks = true"])
        else:
            end = next((i for i in range(feat + 1, len(lines)) if re.match(r"^\s*\[", lines[i])), len(lines))
            hook_line = next((i for i in range(feat + 1, end) if re.match(r"^\s*hooks\s*=", lines[i])), None)
            if hook_line is None:
                lines.insert(feat + 1, "hooks = true")
            else:
                lines[hook_line] = "hooks = true"
        return "\n".join(lines) + "\n"

    @staticmethod
    def strip_config_toml(text: str) -> str:
        lines = [line for line in text.splitlines()
                 if not re.match(r"^\s*model_auto_compact_token_limit\s*=.*reverify rollover", line)]
        return "\n".join(lines) + "\n"

    def install(self, threshold, step, disable_autocompact):
        messages = []
        hooks_file = self.hooks_path()
        data = _load_json_file(hooks_file)
        backup = _backup(hooks_file)
        data["hooks"] = _merge_hooks(data.get("hooks"), self.hook_entries())
        _save_json_file(hooks_file, data)
        messages.append(f"codex: hooks Stop + SessionStart in {hooks_file}" + (f" (backup {backup.name})" if backup else ""))
        config = self.config_path()
        text = config.read_text(encoding="utf-8") if config.is_file() else ""
        cbackup = _backup(config)
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text(self.apply_config_toml(text, disable_autocompact), encoding="utf-8")
        messages.append(f"codex: [features] hooks = true in {config}" + (f" (backup {cbackup.name})" if cbackup else "")
                        + (f"; model_auto_compact_token_limit = {CODEX_NO_COMPACT_LIMIT}" if disable_autocompact else ""))
        if threshold or step:
            messages.append("codex: thresholds are read from the environment; export "
                            f"{ENV_TOKENS}={parse_tokens(threshold, DEFAULT_THRESHOLD)} before starting codex")
        return messages

    def uninstall(self):
        messages = []
        hooks_file = self.hooks_path()
        if hooks_file.is_file():
            data = _load_json_file(hooks_file)
            backup = _backup(hooks_file)
            hooks = _strip_hooks(data.get("hooks"))
            if isinstance(hooks, dict) and not hooks:
                data.pop("hooks", None)
            _save_json_file(hooks_file, data)
            messages.append(f"codex: hooks removed from {hooks_file}" + (f" (backup {backup.name})" if backup else ""))
        config = self.config_path()
        if config.is_file():
            cbackup = _backup(config)
            config.write_text(self.strip_config_toml(config.read_text(encoding="utf-8")), encoding="utf-8")
            messages.append(f"codex: compaction limit line removed from {config}" + (f" (backup {cbackup.name})" if cbackup else "")
                            + "; [features] hooks left as is")
        return messages


# ---- Gemini CLI --------------------------------------------------------------------


class GeminiHarness(Harness):
    name = "gemini"
    exe = "gemini"
    inline_reset = True
    stop_event = "AfterAgent"

    def context_tokens(self, transcript, session_id):
        return gemini_context_tokens(transcript)

    def anchors(self, transcript, session_id):
        return gemini_anchors(transcript)

    def user_message_after(self, transcript, since):
        return gemini_user_message_after(transcript, since)

    def format_block(self, text):
        # AfterAgent: "deny" rejects the response and sends `reason` to the agent as a new prompt.
        return {"decision": "deny", "reason": text}

    def format_receipt(self, result):
        if result.get("inline"):
            return {"hookSpecificOutput": {"hookEventName": "AfterAgent", "clearContext": True}}
        return None

    def format_context(self, text, event):
        name = "BeforeAgent" if event == "before-agent" else "SessionStart"
        return {"hookSpecificOutput": {"hookEventName": name, "additionalContext": text}}

    def hook_command(self, event: str) -> str:
        # Gemini CLI runs command hooks through PowerShell on Windows, where a quoted
        # executable needs the call operator; elsewhere it is a POSIX shell.
        command = super().hook_command(event)
        return ("& " + command) if os.name == "nt" else command

    def launch_args(self, args, opening):
        return list(args) + (["-i", opening] if opening else [])

    @staticmethod
    def settings_file() -> Path:
        return home_dir() / ".gemini" / "settings.json"

    def hook_entries(self) -> Dict[str, Dict[str, Any]]:
        def entry(event: str, timeout_ms: int) -> Dict[str, Any]:
            return {"hooks": [{"name": "reverify-rollover", "type": "command",
                               "command": self.hook_command(event), "timeout": timeout_ms}]}
        return {"AfterAgent": entry("stop", 20000), "BeforeAgent": entry("before-agent", 10000),
                "SessionStart": entry("session-start", 10000)}

    def apply_settings(self, settings: Dict[str, Any], disable_autocompact: bool) -> Dict[str, Any]:
        settings["hooks"] = _merge_hooks(settings.get("hooks"), self.hook_entries())
        if disable_autocompact:
            model = settings.get("model")
            if not isinstance(model, dict):
                model = {}
            model["compressionThreshold"] = 2
            settings["model"] = model
        return settings

    def strip_settings(self, settings: Dict[str, Any]) -> Dict[str, Any]:
        hooks = _strip_hooks(settings.get("hooks"))
        if isinstance(hooks, dict) and not hooks:
            settings.pop("hooks", None)
        model = settings.get("model")
        if isinstance(model, dict) and model.get("compressionThreshold") == 2:
            model.pop("compressionThreshold")
            if not model:
                settings.pop("model")
        return settings

    def install(self, threshold, step, disable_autocompact):
        path = self.settings_file()
        data = _load_json_file(path)
        backup = _backup(path)
        self.apply_settings(data, disable_autocompact)
        _save_json_file(path, data)
        messages = [f"gemini: hooks AfterAgent + BeforeAgent + SessionStart in {path}" + (f" (backup {backup.name})" if backup else "")]
        if disable_autocompact:
            messages.append("gemini: model.compressionThreshold = 2 (never reached)")
        if threshold or step:
            messages.append(f"gemini: thresholds are read from the environment; export {ENV_TOKENS}="
                            f"{parse_tokens(threshold, DEFAULT_THRESHOLD)} before starting gemini")
        return messages

    def uninstall(self):
        path = self.settings_file()
        if not path.is_file():
            return ["gemini: nothing installed"]
        data = _load_json_file(path)
        backup = _backup(path)
        self.strip_settings(data)
        _save_json_file(path, data)
        return [f"gemini: hooks removed from {path}" + (f" (backup {backup.name})" if backup else "")]


# ---- OpenCode ---------------------------------------------------------------------

OPENCODE_PLUGIN_NAME = "reverify-rollover.js"


class OpenCodeHarness(Harness):
    name = "opencode"
    exe = "opencode"
    inline_reset = True            # the plugin opens the fresh session through the SDK
    stop_event = "session.idle"

    def parse_payload(self, payload):
        fields = super().parse_payload(payload)
        fields["tokens"] = payload.get("tokens")
        fields["context_window"] = payload.get("context_window")
        fields["anchors"] = {"first_user_message": payload.get("first_user_message"),
                             "last_user_message": payload.get("last_user_message")}
        return fields

    def context_tokens(self, transcript, session_id):
        return opencode_session_stats(session_id).get("tokens")

    def anchors(self, transcript, session_id):
        stats = opencode_session_stats(session_id)
        return {"first_user_message": stats.get("first_user_message"), "last_user_message": stats.get("last_user_message"),
                "transcript_sha256": None, "transcript_bytes": None}

    def user_message_after(self, transcript, since):
        return False

    def launch_args(self, args, opening):
        return list(args) + (["--prompt", opening] if opening else [])

    @staticmethod
    def config_dir() -> Path:
        override = os.environ.get("OPENCODE_CONFIG_DIR")
        return Path(override) if override else home_dir() / ".config" / "opencode"

    def config_file(self) -> Path:
        return self.config_dir() / "opencode.json"

    def plugin_file(self) -> Path:
        return self.config_dir() / "plugins" / OPENCODE_PLUGIN_NAME

    def plugin_source(self) -> str:
        template = Path(__file__).resolve().parent / "plugins" / "opencode" / OPENCODE_PLUGIN_NAME
        text = template.read_text(encoding="utf-8")
        command = [Path(sys.executable).resolve().as_posix(), Path(__file__).resolve().as_posix()]
        return text.replace("__REVERIFY_COMMAND__", json.dumps(command))

    def install(self, threshold, step, disable_autocompact):
        plugin = self.plugin_file()
        plugin.parent.mkdir(parents=True, exist_ok=True)
        plugin.write_text(self.plugin_source(), encoding="utf-8")
        messages = [f"opencode: plugin written to {plugin}"]
        config = self.config_file()
        data = _load_json_file(config)
        backup = _backup(config)
        if disable_autocompact:
            compaction = data.get("compaction")
            if not isinstance(compaction, dict):
                compaction = {}
            compaction["auto"] = False
            data["compaction"] = compaction
        data.setdefault("$schema", "https://opencode.ai/config.schema.json")
        _save_json_file(config, data)
        messages.append(f"opencode: compaction.auto = {not disable_autocompact} in {config}" + (f" (backup {backup.name})" if backup else ""))
        if threshold or step:
            messages.append(f"opencode: thresholds are read from the environment; export {ENV_TOKENS}="
                            f"{parse_tokens(threshold, DEFAULT_THRESHOLD)} before starting opencode")
        return messages

    def uninstall(self):
        messages = []
        plugin = self.plugin_file()
        if plugin.is_file():
            plugin.unlink()
            messages.append(f"opencode: plugin removed from {plugin}")
        config = self.config_file()
        if config.is_file():
            data = _load_json_file(config)
            backup = _backup(config)
            compaction = data.get("compaction")
            if isinstance(compaction, dict) and compaction.get("auto") is False:
                compaction.pop("auto")
                if not compaction:
                    data.pop("compaction")
            _save_json_file(config, data)
            messages.append(f"opencode: compaction.auto restored in {config}" + (f" (backup {backup.name})" if backup else ""))
        return messages or ["opencode: nothing installed"]


HARNESS_CLASSES = {"claude": ClaudeHarness, "codex": CodexHarness, "gemini": GeminiHarness, "opencode": OpenCodeHarness}


def get_harness(name: str) -> Harness:
    try:
        return HARNESS_CLASSES[name]()
    except KeyError:
        raise ValueError(f"unknown harness {name!r}; choose one of {', '.join(HARNESSES)}")


def detect_harnesses() -> List[str]:
    return [name for name in HARNESSES if shutil.which(HARNESS_CLASSES[name].exe)]


# --------------------------------------------------------------------------- hook entry points


def run_hook(harness: Harness, event: str, payload: Dict[str, Any], env: Optional[Dict[str, str]] = None) -> int:
    env = os.environ if env is None else env
    fields = harness.parse_payload(payload)
    session_id, transcript, cwd = fields["session_id"], fields["transcript"], fields["cwd"]

    if event == "session-start":
        handoff = handoff_path_for(transcript, cwd, harness.name)
        if handoff.is_file():
            text = f"rollover hand-off pending: read {handoff} first (written {describe_age(handoff)})."
            shaped = harness.format_context(text, event)
            if shaped is None:
                print(text)
            else:
                emit(shaped)
        return 0

    if event == "before-agent":
        threshold = threshold_tokens()
        state = load_state(session_id, threshold)
        opening = state.get("opening_pending")
        if opening:
            state["opening_pending"] = None
            save_state(state)
            log_event("opening_injected", harness=harness.name, session=session_id)
            shaped = harness.format_context(str(opening), event)
            if shaped is None:
                print(opening)
            else:
                emit(shaped)
        return 0

    if event in ("stop", "idle"):
        tokens = fields.get("tokens")
        if tokens is None:
            tokens = harness.context_tokens(transcript, session_id)
        window = fields.get("context_window")
        if not window:
            window = harness.context_window(transcript, session_id)

        def anchors_fn() -> Dict[str, Any]:
            base = harness.anchors(transcript, session_id)
            given = fields.get("anchors") or {}
            for key, value in given.items():
                if value:
                    base[key] = str(value)[:ANCHOR_MAX_CHARS]
            return base

        result = run_guard(harness, session_id, transcript, cwd, tokens, anchors_fn, env, window=window)
        if event == "idle":
            # OpenCode plugin protocol: tell the plugin what to do.
            if result["action"] == "block":
                emit({"action": "prompt", "text": result["text"]})
            elif result["action"] == "receipt":
                emit({"action": "rollover" if result.get("inline") else "none", "opening": result["opening"],
                      "handoff": result["receipt"].get("handoff_path")})
            else:
                emit({"action": "none", "why": result.get("why")})
            return 0
        if result["action"] == "block":
            emit(harness.format_block(result["text"]))
        elif result["action"] == "receipt":
            shaped = harness.format_receipt(result)
            if shaped is not None:
                emit(shaped)
        else:
            debug(f"allow: {result.get('why')}")
        return 0

    debug(f"unknown hook event {event!r}")
    return 0


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


# -- Claude-shaped convenience wrappers (kept for the original tests and hooks) -----------------


def run_stop(payload: Dict[str, Any], env: Optional[Dict[str, str]] = None) -> int:
    return run_hook(ClaudeHarness(), "stop", payload, env)


def run_session_start(payload: Dict[str, Any]) -> int:
    return run_hook(ClaudeHarness(), "session-start", payload)


# --------------------------------------------------------------------------- request / status


def _flag_value(argv: List[str], flag: str) -> Optional[str]:
    if flag in argv:
        idx = argv.index(flag)
        if idx + 1 < len(argv):
            return argv[idx + 1]
    return None


def _harness_from(argv: List[str], default: str = "claude") -> Harness:
    return get_harness(_flag_value(argv, "--harness") or default)


def run_request(argv: List[str]) -> int:
    session_id = _flag_value(argv, "--session") or _session_from_env()
    reason = ""
    if "--reason" in argv:
        idx = argv.index("--reason")
        reason = " ".join(a for a in argv[idx + 1:] if not a.startswith("--"))
    key = session_id or cwd_request_key(os.getcwd())
    if "--session" in argv and not session_id:
        print("no session: pass --session <id>")
        return 2
    path = write_request(key, reason)
    log_event("request", key=key, reason=reason, cwd=os.getcwd())
    scope = f"session {session_id}" if session_id else f"this directory ({os.getcwd()})"
    print(f"rollover requested for {scope}; it happens when this turn ends ({path}).")
    return 0


def newest_transcript(project_dir: Path) -> Optional[Path]:
    candidates = [p for p in project_dir.glob("*.jsonl") if p.is_file()]
    return max(candidates, key=lambda p: p.stat().st_mtime) if candidates else None


def _transcript_for_session(session_id: str) -> Optional[Path]:
    projects = home_dir() / ".claude" / "projects"
    if projects.is_dir():
        hits = list(projects.glob(f"*/{_safe_name(session_id)}.jsonl"))
        if hits:
            return hits[0]
    return codex_find_rollout(session_id)


def run_status(argv: List[str]) -> int:
    harness = _harness_from(argv)
    positional = [a for a in argv if not a.startswith("--") and a not in (_flag_value(argv, "--harness"), _flag_value(argv, "--session"))]
    session_id = _flag_value(argv, "--session") or _session_from_env()
    transcript: Optional[Path] = None
    tokens: Optional[int] = None
    if harness.name == "opencode":
        if not session_id:
            print("usage: reverify rollover status --harness opencode --session <id>")
            return 2
        tokens = opencode_session_stats(session_id).get("tokens")
    else:
        if positional:
            transcript = Path(positional[0])
            if transcript.is_dir():
                transcript = newest_transcript(transcript)
        elif session_id:
            transcript = _transcript_for_session(session_id)
        if transcript is None or not transcript.is_file():
            print("usage: reverify rollover status [--harness X] <transcript | project dir> (or run it inside a session)")
            return 2
        session_id = session_id or transcript.stem
        tokens = harness.context_tokens(transcript, session_id)
    threshold = threshold_tokens()
    state = load_state(str(session_id), threshold)
    handoff = handoff_path_for(transcript, os.getcwd(), harness.name)
    print(f"harness    : {harness.name}")
    if transcript is not None:
        print(f"transcript : {transcript}")
    print(f"session    : {session_id}")
    print(f"context    : {tokens if tokens is not None else 'unknown'} tokens")
    print(f"threshold  : {threshold} (step {step_tokens()}; 0 disables)")
    print(f"guard      : next fire at {state.get('next_trigger')} · pending={state.get('pending')} · "
          f"blocks={state.get('blocks')} · rollovers={state.get('rollovers')} · last={state.get('last_outcome')}")
    pending = request_path(str(session_id)).is_file() or request_path(cwd_request_key(os.getcwd())).is_file()
    print(f"request    : {'pending' if pending else 'none'}")
    print(f"hand-off   : {handoff} · {('present, ' + describe_age(handoff)) if handoff.is_file() else 'absent'}")
    return 0


# --------------------------------------------------------------------------- install / uninstall


def hook_command(action: str) -> str:
    """Claude Code hook command (historical helper)."""
    return ClaudeHarness().hook_command(action)


def hook_entries() -> Dict[str, Dict[str, Any]]:
    return ClaudeHarness().hook_entries()


def install_settings(settings: Dict[str, Any], threshold: Optional[str] = None, step: Optional[str] = None,
                     disable_autocompact: bool = True) -> Dict[str, Any]:
    return ClaudeHarness().apply_settings(settings, threshold, step, disable_autocompact)


def uninstall_settings(settings: Dict[str, Any]) -> Dict[str, Any]:
    return ClaudeHarness().strip_settings(settings)


def _selected_harnesses(argv: List[str]) -> List[Harness]:
    chosen = _flag_value(argv, "--harness")
    if chosen:
        names = [n.strip() for n in chosen.split(",") if n.strip()]
    else:
        names = detect_harnesses()
        if not names:
            names = ["claude"]
    return [get_harness(n) for n in names]


def _remedy(harness_name: str, exc: Exception) -> str:
    if harness_name == "opencode" and isinstance(exc, (PermissionError, OSError)):
        return ("opencode: FAILED — cannot write the config dir "
                f"({OpenCodeHarness.config_dir()}): {exc}. Fix its permissions, or set OPENCODE_CONFIG_DIR "
                "to a writable dir and re-run (export the same var before starting opencode).")
    return f"{harness_name}: FAILED — {exc}"


def _run_over_harnesses(harnesses: List[Harness], action) -> int:
    """Run install/uninstall per harness; one harness's failure never stops the others."""
    ok, failed = [], []
    for harness in harnesses:
        try:
            for line in action(harness):
                print(line)
            ok.append(harness.name)
        except Exception as exc:  # a permission / disk problem on one CLI must not block the rest
            print(_remedy(harness.name, exc))
            failed.append(harness.name)
            debug(f"{harness.name} failed: {exc!r}")
    if failed:
        print(f"done: {', '.join(ok) or 'none'}" + f"; failed: {', '.join(failed)}")
    return 0 if ok else 1


def run_install(argv: List[str]) -> int:
    harnesses = _selected_harnesses(argv)
    threshold, step = _flag_value(argv, "--threshold"), _flag_value(argv, "--step")
    disable = "--keep-autocompact" not in argv
    code = _run_over_harnesses(harnesses, lambda h: h.install(threshold, step, disable))
    if "--harness" not in argv:
        print(f"detected: {', '.join(h.name for h in harnesses)} (choose explicitly with --harness a,b)")
    print(f"threshold: {parse_tokens(threshold, threshold_tokens())} tokens, step {parse_tokens(step, step_tokens())}; "
          "sessions already running keep their old settings.")
    return code


def run_uninstall(argv: List[str]) -> int:
    return _run_over_harnesses(_selected_harnesses(argv), lambda h: h.uninstall())


# --------------------------------------------------------------------------- launcher


def resolve_claude() -> str:
    return ClaudeHarness().resolve_exe()


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
    """Ask the CLI to exit (two Ctrl-C at an idle prompt), then force it."""
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
    """Run an agent CLI; on a rollover receipt end the session and start a fresh one.

    Invariants (each has a test):
    - a receipt is consumed exactly once (atomic rename) and never re-used after a restart;
    - a user message that lands after the hand-off cancels that rollover;
    - a receipt with an unknown schema, or one arriving sooner than ``min_interval`` after
      the previous rollover, is ignored (fail closed);
    - the successor's first message quotes the user's original request verbatim.
    """

    def __init__(self, claude_args: List[str], exe: Optional[str] = None, poll: float = 0.5,
                 settle: float = 2.0, graceful: bool = True, max_rollovers: Optional[int] = None,
                 min_interval: float = DEFAULT_MIN_INTERVAL, quiet: bool = False, harness: Optional[Harness] = None):
        self.harness = harness or ClaudeHarness()
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
        cmd = [self.exe or self.harness.resolve_exe()] + self.harness.launch_args(self.claude_args, opening)
        self.launches.append(cmd)
        log_event("launch", harness=self.harness.name, launch_id=launch_id, rollovers=len(self.rollovers))
        return launch_id, subprocess.Popen(cmd, env=env)

    def _discard(self, path: Path, why: str) -> None:
        self.skipped.append(why)
        self._say(why)
        log_event("skipped", why=why, receipt=str(path))
        try:
            path.unlink()
        except OSError:
            pass

    def _consume_reason(self, receipt: Dict[str, Any]) -> Optional[str]:
        """Why this receipt must NOT be consumed (None = consume it). Pure, so it is unit-tested."""
        if receipt.get("schema") != RECEIPT_SCHEMA:
            return f"receipt schema {receipt.get('schema')!r} is not {RECEIPT_SCHEMA}; ignored"
        if self._last_rollover_at is not None and time.time() - self._last_rollover_at < self.min_interval:
            return "rollover requested too soon after the previous one; ignored"
        if self.harness.user_message_after(receipt.get("transcript_path"), float(receipt.get("written_epoch") or 0.0)):
            return "a user message arrived after the hand-off; this rollover is off"
        return None

    def wait_for_receipt(self, launch_id: str, proc: "subprocess.Popen[Any]") -> Optional[Dict[str, Any]]:
        path = receipt_path(launch_id)
        while proc.poll() is None:
            receipt = _read_json(path) if path.is_file() else None
            if receipt is None:
                time.sleep(self.poll)
                continue
            # Fence: give a queued user message the chance to land before deciding.
            time.sleep(self.settle)
            if proc.poll() is not None:
                break
            reason = self._consume_reason(receipt)
            if reason:
                self._discard(path, reason)
                continue
            try:
                os.replace(path, path.with_suffix(".consumed.json"))
            except OSError:
                pass
            return receipt
        return None

    def run(self) -> int:
        self._say(f"auto-rollover on for {self.harness.name}; built-in compaction stays off")
        previous = signal.getsignal(signal.SIGINT)
        try:
            signal.signal(signal.SIGINT, signal.SIG_IGN)
        except (ValueError, OSError):
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
                log_event("rollover", harness=self.harness.name, launch_id=launch_id, session=receipt.get("session_id"),
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


LAUNCHER_FLAGS_WITH_VALUE = ("--claude", "--exe", "--harness", "--poll", "--settle", "--max-rollovers", "--min-interval")
LAUNCHER_FLAGS = ("--force-kill", "--quiet")


def split_launcher_args(argv: List[str]) -> Tuple[List[str], List[str]]:
    """Launcher options vs. arguments passed through to the CLI (``--`` separates explicitly)."""
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


def resolve_run_harness(own: List[str], passthrough: List[str]) -> Tuple[Harness, List[str]]:
    """Which CLI to launch: --harness, else a leading CLI name, else the obvious one on PATH."""
    name = _flag_value(own, "--harness")
    if not name and passthrough and passthrough[0] in HARNESSES:
        name, passthrough = passthrough[0], passthrough[1:]
    if not name:
        found = detect_harnesses()
        if "claude" in found:
            name = "claude"
        elif len(found) == 1:
            name = found[0]
        elif not found:
            raise FileNotFoundError("no agent CLI on PATH (claude, codex, gemini, opencode)")
        else:
            raise ValueError(f"several CLIs on PATH ({', '.join(found)}); say which: reverify rollover run {found[0]} ...")
    return get_harness(name), passthrough


def run_launcher(argv: List[str]) -> int:
    own, passthrough = split_launcher_args(list(argv))
    try:
        harness, passthrough = resolve_run_harness(own, passthrough)
    except (FileNotFoundError, ValueError) as exc:
        print(str(exc))
        return 2
    max_rollovers = _flag_value(own, "--max-rollovers")
    launcher = Launcher(
        passthrough,
        exe=_flag_value(own, "--exe") or _flag_value(own, "--claude"),
        poll=float(_flag_value(own, "--poll") or 0.5),
        settle=float(_flag_value(own, "--settle") or 2.0),
        graceful="--force-kill" not in own,
        max_rollovers=int(max_rollovers) if max_rollovers else None,
        min_interval=float(_flag_value(own, "--min-interval") or DEFAULT_MIN_INTERVAL),
        quiet="--quiet" in own,
        harness=harness,
    )
    return launcher.run()


# --------------------------------------------------------------------------- doctor / instructions


def _command_resolves(command: str) -> Tuple[bool, str]:
    """A hook command we wrote: does its interpreter and module still exist?"""
    quoted = re.findall(r'"([^"]+)"', command)
    if len(quoted) < 2:
        return False, "unexpected command shape"
    for part in quoted[:2]:
        if not Path(part).exists():
            return False, f"missing: {part}"
    return True, "ok"


def _hooks_of(container: Any, events: Iterable[str]) -> Dict[str, Optional[str]]:
    found: Dict[str, Optional[str]] = {}
    hooks = container if isinstance(container, dict) else {}
    for event in events:
        command = None
        for entry in hooks.get(event, []) or []:
            if isinstance(entry, dict) and _is_ours(entry):
                for h in entry.get("hooks", []):
                    if isinstance(h, dict) and any(m in str(h.get("command", "")) for m in HOOK_MARKERS):
                        command = str(h.get("command"))
        found[event] = command
    return found


def doctor_report() -> List[Dict[str, Any]]:
    """Per harness: on PATH, hooks wired, commands resolvable, native compaction off."""
    rows: List[Dict[str, Any]] = []
    for name in HARNESSES:
        harness = get_harness(name)
        row: Dict[str, Any] = {"harness": name, "on_path": bool(shutil.which(harness.exe)), "hooks": {},
                               "compaction_off": None, "problems": []}
        try:
            if name == "claude":
                data = _load_json_file(settings_path())
                row["hooks"] = _hooks_of(data.get("hooks"), ("Stop", "SessionStart"))
                row["compaction_off"] = data.get("autoCompactEnabled") is False
            elif name == "codex":
                data = _load_json_file(CodexHarness.hooks_path())
                row["hooks"] = _hooks_of(data.get("hooks"), ("Stop", "SessionStart"))
                config = CodexHarness.config_path()
                text = config.read_text(encoding="utf-8") if config.is_file() else ""
                row["compaction_off"] = "model_auto_compact_token_limit" in text
                if not re.search(r"^\s*hooks\s*=\s*true", text, re.M):
                    row["problems"].append("[features] hooks is not true in config.toml")
            elif name == "gemini":
                data = _load_json_file(GeminiHarness.settings_file())
                row["hooks"] = _hooks_of(data.get("hooks"), ("AfterAgent", "BeforeAgent", "SessionStart"))
                model = data.get("model") if isinstance(data.get("model"), dict) else {}
                row["compaction_off"] = isinstance(model.get("compressionThreshold"), (int, float)) and model["compressionThreshold"] > 1
            else:
                harness_oc = OpenCodeHarness()
                plugin = harness_oc.plugin_file()
                row["hooks"] = {"plugin": str(plugin) if plugin.is_file() else None}
                data = _load_json_file(harness_oc.config_file())
                compaction = data.get("compaction") if isinstance(data.get("compaction"), dict) else {}
                row["compaction_off"] = compaction.get("auto") is False
        except Exception as exc:  # unreadable config is a finding, not a crash
            row["problems"].append(f"cannot read config: {exc}")
        for event, command in row["hooks"].items():
            if command is None:
                row["problems"].append(f"{event}: not installed")
            elif event != "plugin":
                ok, why = _command_resolves(command)
                if not ok:
                    row["problems"].append(f"{event}: {why}")
        rows.append(row)
    return rows


def run_doctor(argv: List[str]) -> int:
    rows = doctor_report()
    threshold = threshold_tokens()
    print(f"threshold  : {threshold} tokens (step {step_tokens()}); state dir {state_dir()}")
    for row in rows:
        installed = row["hooks"] and all(v for v in row["hooks"].values())
        mark = "ok" if installed and not row["problems"] else ("--" if not row["on_path"] and not installed else "!!")
        print(f"{mark:2} {row['harness']:<9} on PATH: {'yes' if row['on_path'] else 'no ':<3}  hooks: {'yes' if installed else 'no ':<3}  "
              f"native compaction off: {'yes' if row['compaction_off'] else 'no'}")
        for problem in row["problems"]:
            print(f"     - {problem}")
    events = state_dir() / "events.jsonl"
    if events.is_file():
        tail = events.read_text(encoding="utf-8").splitlines()[-3:]
        print("recent     : " + " | ".join(t[:110] for t in tail))
    missing = [r["harness"] for r in rows if r["on_path"] and (not r["hooks"] or not all(r["hooks"].values()))]
    if missing:
        print(f"to install : reverify rollover install --harness {','.join(missing)}")
    return 0 if not any(r["problems"] for r in rows if r["on_path"]) else 1


INSTRUCTIONS_SNIPPET = """## Context rollover (reverify)

State lives in files; the conversation is a cache. Built-in compaction is off.
- At the start of a session, if a line says "rollover hand-off pending", read that file first,
  then pull details on demand from the memory index it points to.
- Write conclusions into memory/notes files as you reach milestones; do not wait to be asked.
- When a large task is done and the next one is unrelated, run
  `reverify rollover request --reason "<why>"` and finish your reply; the hand-off happens at
  the end of that turn.
- Never tell the user to clear or compact anything; that is handled for them.
"""


def run_instructions(argv: List[str]) -> int:
    target = _flag_value(argv, "--write")
    if not target:
        print(INSTRUCTIONS_SNIPPET, end="")
        return 0
    path = Path(target)
    existing = path.read_text(encoding="utf-8") if path.is_file() else ""
    if "## Context rollover (reverify)" in existing:
        print(f"{path}: already has the snippet")
        return 0
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        if existing and not existing.endswith("\n"):
            handle.write("\n")
        if existing:
            handle.write("\n")
        handle.write(INSTRUCTIONS_SNIPPET)
    print(f"{path}: snippet appended")
    return 0


# --------------------------------------------------------------------------- entry point

USAGE = """reverify rollover <action> [options]

  install [--harness claude,codex,gemini,opencode] [--threshold 200k] [--step 100k] [--keep-autocompact]
                       wire the hooks (default: every CLI found on PATH) and turn built-in compaction off; backups kept
  uninstall [--harness ...]
                       remove the hooks, restore compaction
  doctor               what is installed, whether the hook commands still resolve, recent events
  claude|codex|gemini|opencode [cli args]
                       start that CLI through the launcher (fresh session on every receipt)
  run [--harness X] [--max-rollovers N] [--settle S] [--min-interval S] [--force-kill] [--quiet] [--] <cli args>
                       same, long form; without --harness the CLI is the first argument or the obvious one on PATH
  request [--reason ...] [--session <id>]
                       (run by the model, inside a session) roll over at the end of this turn
  status [--harness X] [<transcript | project dir>] [--session <id>]
                       tokens, threshold, guard state, hand-off
  instructions [--write AGENTS.md|CLAUDE.md|GEMINI.md]
                       the short protocol paragraph for the model's instruction file
  hook <harness> <stop|session-start|before-agent|idle>
                       hook entry points (read the hook JSON on stdin)
"""


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    configure_streams()
    action = argv[0] if argv else "help"
    rest = argv[1:]
    if action in ("stop", "session-start"):          # historical Claude-only entry points
        action, rest = "hook", ["claude", action] + rest
    try:
        if action == "hook":
            if len(rest) < 2:
                return 0
            return run_hook(get_harness(rest[0]), rest[1], read_hook_input())
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
    if action in HARNESSES:
        return run_launcher(["--harness", action] + rest)
    if action == "doctor":
        return run_doctor(rest)
    if action == "instructions":
        return run_instructions(rest)
    print(USAGE)
    return 0 if action in ("help", "-h", "--help") else 2


if __name__ == "__main__":
    sys.exit(main())
