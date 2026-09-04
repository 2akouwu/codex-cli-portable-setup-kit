"""Claude Code rollover: fresh sessions instead of compaction, with a fail-closed hand-off.

What must hold: the guard measures the live context from the transcript; crossing the
threshold (or a model request) blocks one stop and asks for the hand-off file; a receipt is
issued only when that file was really written and well-formed; the launcher consumes a
receipt exactly once, cancels a rollover when a user message landed meanwhile, ignores
unknown schemas and too-frequent receipts, and opens the successor with the user's verbatim
request; install / uninstall are idempotent and reversible.
"""

import io
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path

tools_root = Path(__file__).resolve().parent.parent
if str(tools_root) not in sys.path:
    sys.path.insert(0, str(tools_root))

import claude_rollover as cr  # noqa: E402


def assistant_line(cache_read, cache_create=0, output=10, sidechain=False, when="2026-09-04T10:00:00.000Z"):
    return json.dumps({
        "type": "assistant", "isSidechain": sidechain, "timestamp": when,
        "message": {"role": "assistant", "content": [{"type": "text", "text": "x"}],
                    "usage": {"input_tokens": 1, "cache_read_input_tokens": cache_read,
                              "cache_creation_input_tokens": cache_create, "output_tokens": output}},
    })


def user_line(text="hi", when="2026-09-04T09:59:00.000Z", tool_result=False, meta=False):
    content = [{"type": "tool_result", "tool_use_id": "t", "content": "ok"}] if tool_result else text
    record = {"type": "user", "timestamp": when, "message": {"role": "user", "content": content}}
    if tool_result:
        record["toolUseResult"] = {"stdout": "ok"}
    if meta:
        record["isMeta"] = True
    return json.dumps(record)


HANDOFF_OK = textwrap.dedent("""\
    # Rollover hand-off
    written: now
    ## Task and goal
    fix the thing
    ## Decisions the user made
    none
    ## Next step
    run the tests
    """)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()   # macOS: /var -> /private/var
        self.project = self.root / "projects" / "C------"
        (self.project / "memory").mkdir(parents=True)
        self.transcript = self.project / "sess-1.jsonl"
        self.state = self.root / "state"
        self._env = dict(os.environ)
        os.environ[cr.ENV_STATE_DIR] = str(self.state)
        for key in (cr.ENV_TOKENS, cr.ENV_STEP, cr.ENV_LAUNCH_ID, cr.ENV_SESSION):
            os.environ.pop(key, None)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env)
        self.tmp.cleanup()

    def write_transcript(self, *lines):
        self.transcript.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def stop(self, lines, stop_hook_active=False, env=None):
        self.write_transcript(*lines)
        payload = {"session_id": "sess-1", "transcript_path": str(self.transcript),
                   "hook_event_name": "Stop", "stop_hook_active": stop_hook_active, "cwd": str(self.root)}
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(cr.run_stop(payload, env=env), 0)
        text = out.getvalue().strip()
        return json.loads(text) if text else None

    @property
    def handoff(self):
        return self.project / "memory" / cr.HANDOFF_NAME


class TokensAndTranscript(Base):
    def test_parse_tokens(self):
        self.assertEqual(cr.parse_tokens("200k", 1), 200_000)
        self.assertEqual(cr.parse_tokens("0.5m", 1), 500_000)
        self.assertEqual(cr.parse_tokens("150000", 1), 150_000)
        self.assertEqual(cr.parse_tokens("", 7), 7)
        self.assertEqual(cr.parse_tokens("garbage", 7), 7)

    def test_context_is_last_main_assistant_usage(self):
        self.write_transcript(user_line(), assistant_line(1000), assistant_line(900_000, sidechain=True),
                              assistant_line(50_000, 3_000, 500), user_line())
        self.assertEqual(cr.context_tokens(self.transcript), 1 + 50_000 + 3_000 + 500)
        self.assertIsNone(cr.context_tokens(self.project / "missing.jsonl"))
        self.assertIsNone(cr.context_tokens(None))

    def test_context_from_tail_of_large_transcript(self):
        filler = json.dumps({"type": "user", "message": {"role": "user", "content": "y" * 5000}})
        self.write_transcript(*([filler] * 1200 + [assistant_line(250_000)]))
        self.assertGreater(self.transcript.stat().st_size, cr.TAIL_BYTES)
        self.assertEqual(cr.context_tokens(self.transcript), 250_011)

    def test_anchors_are_verbatim_and_skip_tool_results_meta_and_commands(self):
        self.write_transcript(
            user_line("<command-name>/clear</command-name>", "2026-09-04T09:00:00.000Z"),
            user_line("please map the loader", "2026-09-04T09:01:00.000Z"),
            user_line("x", "2026-09-04T09:02:00.000Z", tool_result=True),
            user_line("system note", "2026-09-04T09:03:00.000Z", meta=True),
            assistant_line(1000),
            user_line("now the exports", "2026-09-04T09:04:00.000Z"),
            user_line("y", "2026-09-04T09:05:00.000Z", tool_result=True),
        )
        anchors = cr.transcript_anchors(self.transcript)
        self.assertEqual(anchors["first_user_message"], "please map the loader")
        self.assertEqual(anchors["last_user_message"], "now the exports")
        self.assertEqual(len(anchors["transcript_sha256"]), 64)
        self.assertEqual(anchors["transcript_bytes"], self.transcript.stat().st_size)

    def test_user_message_after_ignores_tool_results(self):
        since = cr.parse_iso("2026-09-04T10:00:00Z")
        self.write_transcript(user_line("a", "2026-09-04T09:00:00.000Z"), assistant_line(10),
                              user_line("r", "2026-09-04T10:00:05.000Z", tool_result=True))
        self.assertFalse(cr.user_message_after(self.transcript, since))
        self.write_transcript(user_line("a", "2026-09-04T09:00:00.000Z"), assistant_line(10),
                              user_line("new instruction", "2026-09-04T10:00:05.000Z"))
        self.assertTrue(cr.user_message_after(self.transcript, since))
        self.assertFalse(cr.user_message_after(self.project / "missing.jsonl", since))


class Guard(Base):
    def test_below_threshold_is_silent(self):
        self.assertIsNone(self.stop([assistant_line(120_000)]))
        self.assertFalse(cr.state_path("sess-1").exists())

    def test_threshold_blocks_once_then_receipt_only_with_a_real_handoff(self):
        first = self.stop([assistant_line(205_000)])
        self.assertEqual(first["decision"], "block")
        self.assertIn(str(self.handoff), first["reason"])
        self.assertIn("205k", first["reason"])
        self.assertIn("MEMORY.md", first["reason"])
        self.assertIn("## Next step", first["reason"])
        state = cr.load_state("sess-1", cr.DEFAULT_THRESHOLD)
        self.assertTrue(state["pending"])

        # the model stops again without writing the file -> fail closed, no receipt, re-armed
        self.assertIsNone(self.stop([assistant_line(209_000)], stop_hook_active=True))
        state = cr.load_state("sess-1", cr.DEFAULT_THRESHOLD)
        self.assertFalse(state["pending"])
        self.assertEqual(state["rollovers"], 0)
        self.assertTrue(state["last_outcome"].startswith("handoff_rejected"))
        self.assertEqual(state["next_trigger"], 209_011 + cr.DEFAULT_STEP)
        self.assertFalse(cr.receipt_path("sess-1").exists())

        # quiet until the re-armed trigger, then block again; this time the hand-off is written
        self.assertIsNone(self.stop([assistant_line(300_000)]))
        self.assertEqual(self.stop([assistant_line(310_000)])["decision"], "block")
        self.handoff.write_text(HANDOFF_OK, encoding="utf-8")
        self.assertIsNone(self.stop([assistant_line(312_000)], stop_hook_active=True))
        receipt = json.loads(cr.receipt_path("sess-1").read_text(encoding="utf-8"))
        self.assertEqual(receipt["schema"], cr.RECEIPT_SCHEMA)
        self.assertEqual(receipt["handoff_path"], str(self.handoff))
        self.assertEqual(receipt["context_tokens"], 312_011)
        self.assertEqual(receipt["reason"], "threshold")
        self.assertEqual(receipt["first_user_message"], None)
        self.assertEqual(len(receipt["transcript_sha256"]), 64)
        state = cr.load_state("sess-1", cr.DEFAULT_THRESHOLD)
        self.assertEqual(state["rollovers"], 1)
        self.assertEqual(state["blocks"], 2)
        events = [json.loads(l)["event"] for l in (self.state / "events.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual(events, ["block", "handoff_rejected", "block", "receipt"])

    def test_stale_handoff_is_rejected(self):
        self.handoff.write_text(HANDOFF_OK, encoding="utf-8")
        old = time.time() - 600
        os.utime(self.handoff, (old, old))
        self.stop([assistant_line(205_000)])
        self.assertIsNone(self.stop([assistant_line(206_000)], stop_hook_active=True))
        self.assertIn("not rewritten", cr.load_state("sess-1", cr.DEFAULT_THRESHOLD)["last_outcome"])

    def test_malformed_or_oversized_handoff_is_rejected(self):
        self.stop([assistant_line(205_000)])
        self.handoff.write_text("just one line, no sections", encoding="utf-8")
        self.assertIsNone(self.stop([assistant_line(206_000)], stop_hook_active=True))
        self.assertIn("fewer than 3 sections", cr.load_state("sess-1", cr.DEFAULT_THRESHOLD)["last_outcome"])
        self.assertEqual(self.stop([assistant_line(320_000)])["decision"], "block")
        self.handoff.write_text(HANDOFF_OK + "x" * cr.HANDOFF_MAX_BYTES, encoding="utf-8")
        self.assertIsNone(self.stop([assistant_line(321_000)], stop_hook_active=True))
        self.assertIn("larger than", cr.load_state("sess-1", cr.DEFAULT_THRESHOLD)["last_outcome"])

    def test_model_request_triggers_regardless_of_size(self):
        os.environ[cr.ENV_SESSION] = "sess-1"
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(cr.run_request(["--reason", "switching", "to", "another", "task"]), 0)
        self.assertIn("rollover requested", out.getvalue())
        blocked = self.stop([assistant_line(40_000)])
        self.assertEqual(blocked["decision"], "block")
        self.assertIn('You asked for a rollover ("switching to another task")', blocked["reason"])
        self.assertFalse(cr.request_path("sess-1").exists())
        self.handoff.write_text(HANDOFF_OK, encoding="utf-8")
        self.assertIsNone(self.stop([assistant_line(41_000)], stop_hook_active=True))
        receipt = json.loads(cr.receipt_path("sess-1").read_text(encoding="utf-8"))
        self.assertEqual(receipt["reason"], "request: switching to another task")

    def test_request_needs_a_session(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(cr.run_request([]), 2)

    def test_receipt_is_keyed_by_launch_id_when_launched(self):
        env = dict(os.environ)
        env[cr.ENV_LAUNCH_ID] = "launch-abc"
        self.stop([assistant_line(205_000)], env=env)
        self.handoff.write_text(HANDOFF_OK, encoding="utf-8")
        self.stop([assistant_line(206_000)], stop_hook_active=True, env=env)
        self.assertTrue(cr.receipt_path("launch-abc").exists())
        self.assertFalse(cr.receipt_path("sess-1").exists())

    def test_env_threshold_and_disable(self):
        os.environ[cr.ENV_TOKENS] = "50k"
        self.assertEqual(self.stop([assistant_line(60_000)])["decision"], "block")
        os.environ[cr.ENV_TOKENS] = "0"
        self.assertIsNone(self.stop([assistant_line(900_000)]))

    def test_no_usage_or_missing_transcript_allows(self):
        self.assertIsNone(self.stop([user_line()]))
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(cr.run_stop({"session_id": "x", "transcript_path": str(self.project / "nope.jsonl")}), 0)
        self.assertEqual(out.getvalue(), "")

    def test_no_memory_dir_falls_back_to_cwd(self):
        other = self.root / "projects" / "other"
        other.mkdir()
        transcript = other / "s.jsonl"
        transcript.write_text(assistant_line(250_000) + "\n", encoding="utf-8")
        out = io.StringIO()
        with redirect_stdout(out):
            cr.run_stop({"session_id": "s", "transcript_path": str(transcript), "cwd": str(self.root)})
        data = json.loads(out.getvalue())
        self.assertEqual(data["decision"], "block")
        self.assertIn(str(self.root / ".claude" / cr.HANDOFF_NAME), data["reason"])
        self.assertIn("whichever memory index", data["reason"])

    def test_main_fails_open_on_bad_stdin(self):
        sys.stdin = io.StringIO("not json")
        try:
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(cr.main(["stop"]), 0)
            self.assertEqual(out.getvalue(), "")
        finally:
            sys.stdin = sys.__stdin__


class SessionStartAndStatus(Base):
    def test_session_start_prints_one_pointer_only_when_handoff_exists(self):
        out = io.StringIO()
        with redirect_stdout(out):
            cr.run_session_start({"transcript_path": str(self.transcript), "source": "startup"})
        self.assertEqual(out.getvalue(), "")
        self.handoff.write_text(HANDOFF_OK, encoding="utf-8")
        out = io.StringIO()
        with redirect_stdout(out):
            cr.run_session_start({"transcript_path": str(self.transcript), "source": "clear"})
        self.assertEqual(out.getvalue().count("\n"), 1)
        self.assertIn(str(self.handoff), out.getvalue())

    def test_status_on_directory_picks_newest(self):
        self.write_transcript(assistant_line(42_000))
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(cr.run_status([str(self.project)]), 0)
        text = out.getvalue()
        self.assertIn("42011 tokens", text)
        self.assertIn("hand-off   :", text)
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(cr.run_status([]), 2)


class Settings(Base):
    def test_install_is_idempotent_and_uninstall_restores(self):
        settings = {"model": "sonnet", "autoCompactWindow": "200k", "precomputeCompactionEnabled": True,
                    "hooks": {"Stop": [{"hooks": [{"type": "command", "command": "python rollover_guard.py stop"}]}],
                              "SessionStart": [{"matcher": "compact", "hooks": [{"type": "command", "command": "reverify ledger --context"}]}]}}
        cr.install_settings(settings, threshold="150k")
        cr.install_settings(settings, threshold="150k")
        self.assertIs(settings["autoCompactEnabled"], False)
        self.assertNotIn("autoCompactWindow", settings)
        self.assertEqual(len(settings["hooks"]["Stop"]), 1)
        self.assertIn("claude_rollover.py", settings["hooks"]["Stop"][0]["hooks"][0]["command"])
        self.assertEqual(len(settings["hooks"]["SessionStart"]), 2)
        self.assertEqual(settings["hooks"]["SessionStart"][0]["hooks"][0]["command"], "reverify ledger --context")
        self.assertEqual(settings["env"][cr.ENV_TOKENS], "150000")
        cr.uninstall_settings(settings)
        self.assertNotIn("autoCompactEnabled", settings)
        self.assertNotIn("Stop", settings["hooks"])
        self.assertEqual(len(settings["hooks"]["SessionStart"]), 1)
        self.assertNotIn("env", settings)
        self.assertEqual(settings["model"], "sonnet")

    def test_install_and_uninstall_on_disk_keep_a_backup(self):
        path = self.root / "settings.json"
        path.write_text(json.dumps({"theme": "dark"}), encoding="utf-8")
        os.environ[cr.ENV_SETTINGS] = str(path)
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(cr.run_install(["--threshold", "180k", "--step", "50k"]), 0)
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertIs(data["autoCompactEnabled"], False)
        self.assertEqual(data["env"], {cr.ENV_TOKENS: "180000", cr.ENV_STEP: "50000"})
        self.assertTrue(any(p.name.startswith("settings.json.bak-reverify-") for p in self.root.iterdir()))
        with redirect_stdout(io.StringIO()):
            self.assertEqual(cr.run_uninstall([]), 0)
        self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"theme": "dark"})


STUB = textwrap.dedent("""\
    import os, sys, time, json
    log = sys.argv[1]
    with open(log, "a", encoding="utf-8") as h:
        h.write(json.dumps({"argv": sys.argv[2:], "launch": os.environ.get("REVERIFY_ROLLOVER_LAUNCH_ID")}) + "\\n")
    stop_flag = os.environ.get("STUB_EXIT_FLAG")
    for _ in range(600):
        if stop_flag and os.path.exists(stop_flag):
            sys.exit(0)
        time.sleep(0.05)
    sys.exit(0)
    """)


class LauncherArgs(unittest.TestCase):
    def test_split_with_and_without_separator(self):
        self.assertEqual(cr.split_launcher_args(["--quiet", "--", "--permission-mode", "auto"]),
                         (["--quiet"], ["--permission-mode", "auto"]))
        self.assertEqual(cr.split_launcher_args(["--settle", "1", "--permission-mode", "auto", "--force-kill"]),
                         (["--settle", "1", "--force-kill"], ["--permission-mode", "auto"]))
        self.assertEqual(cr.split_launcher_args([]), ([], []))


class LauncherLoop(Base):
    """A stub stands in for Claude Code: it records how it was launched and waits to be ended.

    Receipts and the stub's exit flag are produced on timers, while the launcher is waiting,
    the way the real guard and the real user act.
    """

    def setUp(self):
        super().setUp()
        self.stub = self.root / "stub.py"
        self.stub.write_text(STUB, encoding="utf-8")
        self.log = self.root / "launches.jsonl"
        self.exit_flag = self.root / "exit.flag"
        os.environ["STUB_EXIT_FLAG"] = str(self.exit_flag)
        self.timers = []

    def tearDown(self):
        for timer in self.timers:
            timer.cancel()
            timer.join(timeout=5)
        super().tearDown()

    def later(self, delay, fn, *args, **kwargs):
        timer = threading.Timer(delay, fn, args=args, kwargs=kwargs)
        timer.daemon = True
        timer.start()
        self.timers.append(timer)

    def launches(self):
        return [json.loads(l) for l in self.log.read_text(encoding="utf-8").splitlines()]

    def make_receipt(self, launch_id, **extra):
        self.write_transcript(user_line("map the loader", "2026-09-04T09:00:00.000Z"), assistant_line(250_000))
        self.handoff.write_text(HANDOFF_OK, encoding="utf-8")
        receipt = {"schema": cr.RECEIPT_SCHEMA, "session_id": "sess-1", "launch_id": launch_id,
                   "transcript_path": str(self.transcript), "handoff_path": str(self.handoff),
                   "context_tokens": 250_011, "reason": "threshold", "written_at": cr.now_iso(),
                   "written_epoch": time.time(), "first_user_message": "map the loader",
                   "last_user_message": "map the loader"}
        receipt.update(extra)
        cr._write_json(cr.receipt_path(launch_id), receipt)

    def stop_stub(self):
        self.exit_flag.write_text("done", encoding="utf-8")

    def run_launcher(self, on_launch, max_rollovers=None, min_interval=0.0):
        launcher = cr.Launcher([str(self.stub), str(self.log)], exe=sys.executable, poll=0.05, settle=0.05,
                               graceful=False, max_rollovers=max_rollovers, min_interval=min_interval, quiet=True)
        original_spawn = launcher.spawn

        def spawn(opening):
            launch_id, proc = original_spawn(opening)
            on_launch(launch_id, len(launcher.launches))
            return launch_id, proc

        launcher.spawn = spawn
        return launcher, launcher.run()

    def test_receipt_ends_session_and_relaunches_with_verbatim_anchor(self):
        def on_launch(launch_id, n):
            if n == 1:
                self.later(0.3, self.make_receipt, launch_id)
            else:
                self.later(0.3, self.stop_stub)

        launcher, code = self.run_launcher(on_launch)
        self.assertEqual(code, 0)
        self.assertEqual(len(launcher.rollovers), 1)
        runs = self.launches()
        self.assertEqual(len(runs), 2)
        self.assertEqual(runs[0]["argv"], [])
        opening = runs[1]["argv"][-1]
        self.assertIn(str(self.handoff), opening)
        self.assertIn("«map the loader»", opening)
        self.assertNotEqual(runs[0]["launch"], runs[1]["launch"])
        consumed = list((self.state / "receipts").glob("*.consumed.json"))
        self.assertEqual(len(consumed), 1)
        self.assertEqual(list((self.state / "receipts").glob("*.json")), consumed)
        events = [json.loads(l)["event"] for l in (self.state / "events.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual(events, ["launch", "rollover", "launch"])

    def test_user_message_after_handoff_cancels_the_rollover(self):
        def arm(launch_id):
            self.make_receipt(launch_id, written_epoch=time.time() - 60)
            with self.transcript.open("a", encoding="utf-8") as handle:
                handle.write(user_line("wait, one more thing", cr.now_iso()) + "\n")

        def on_launch(launch_id, n):
            self.later(0.3, arm, launch_id)
            self.later(1.2, self.stop_stub)

        launcher, code = self.run_launcher(on_launch)
        self.assertEqual(code, 0)
        self.assertEqual(launcher.rollovers, [])
        self.assertEqual(len(self.launches()), 1)
        self.assertTrue(any("user message" in s for s in launcher.skipped))
        self.assertFalse(any((self.state / "receipts").glob("*.json")))

    def test_unknown_schema_and_too_soon_are_ignored(self):
        def on_launch(launch_id, n):
            if n == 1:
                self.later(0.3, self.make_receipt, launch_id, schema=99)
                self.later(1.0, self.make_receipt, launch_id)
            elif n == 2:
                self.later(0.3, self.make_receipt, launch_id)
                self.later(1.2, self.stop_stub)

        launcher, code = self.run_launcher(on_launch, min_interval=60.0)
        self.assertEqual(code, 0)
        self.assertEqual(len(launcher.rollovers), 1)
        self.assertEqual(len(self.launches()), 2)
        self.assertTrue(any("schema" in s for s in launcher.skipped))
        self.assertTrue(any("too soon" in s for s in launcher.skipped))

    def test_max_rollovers_stops_the_loop(self):
        def on_launch(launch_id, n):
            self.later(0.3, self.make_receipt, launch_id)

        launcher, code = self.run_launcher(on_launch, max_rollovers=2)
        self.assertEqual(code, 0)
        self.assertEqual(len(launcher.rollovers), 2)
        self.assertEqual(len(self.launches()), 2)

    def test_exit_without_receipt_returns_child_code(self):
        def on_launch(launch_id, n):
            self.later(0.3, self.stop_stub)

        launcher, code = self.run_launcher(on_launch)
        self.assertEqual(code, 0)
        self.assertEqual(launcher.rollovers, [])


class OpeningPrompt(unittest.TestCase):
    def test_opening_prompt_quotes_both_anchors_when_different(self):
        text = cr.opening_prompt({"handoff_path": "H", "first_user_message": "A", "last_user_message": "B"})
        self.assertIn("Read the hand-off first: H", text)
        self.assertIn("«A»", text)
        self.assertIn("«B»", text)
        text = cr.opening_prompt({"handoff_path": "H", "first_user_message": "A", "last_user_message": "A"})
        self.assertEqual(text.count("«A»"), 1)


class HookCommand(unittest.TestCase):
    def test_hook_command_points_at_this_module_and_interpreter(self):
        command = cr.hook_command("stop")
        self.assertIn("claude_rollover.py", command)
        self.assertTrue(command.endswith(" stop"))
        self.assertIn(Path(sys.executable).resolve().as_posix(), command)

    def test_module_runs_standalone_and_prints_usage(self):
        proc = subprocess.run([sys.executable, str(tools_root / "claude_rollover.py"), "help"],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("reverify rollover <action>", proc.stdout)


if __name__ == "__main__":
    unittest.main()
