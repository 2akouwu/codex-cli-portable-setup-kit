"""The ledger is the state; the context is a cache.

These tests pin the property the whole design rests on: clearing the context
(a fresh agent, a fresh process, a fresh MCP host) loses nothing the tools ever
grounded — and brings back what they refuted, so the same wrong prior is not
proposed again.
"""

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

tools_root = Path(__file__).resolve().parent.parent
if str(tools_root) not in sys.path:
    sys.path.insert(0, str(tools_root))

from ledger import (  # noqa: E402
    Ledger, context_for_directory, hook_config, list_ledgers, ledger_dir, tier_of,
    PROVEN, TESTED, ENV_DIR,
)
from agent import ReconstructionAgent, compact_facts, build_prompt, binary_facts, demo_proposer  # noqa: E402
from verifier import VERIFIED, REFUTED, OBSERVED  # noqa: E402
import mcp_server  # noqa: E402
import cli  # noqa: E402


def fact(kind, params, verdict=VERIFIED, weight=0.5, detail="ok", evidence=None, note=""):
    return {"kind": kind, "params": params, "verdict": verdict, "weight": weight, "detail": detail,
            "evidence": evidence or {}, "note": note, "id": None, "depends_on": []}


class SeqProposer:
    def __init__(self, responses):
        self.responses, self.calls = responses, 0

    def __call__(self, prompt):
        r = self.responses[min(self.calls, len(self.responses) - 1)]
        self.calls += 1
        return r


class RecordingProposer(SeqProposer):
    def __init__(self, responses):
        super().__init__(responses)
        self.prompts = []

    def __call__(self, prompt):
        self.prompts.append(prompt)
        return super().__call__(prompt)


class TempDirCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self._env = os.environ.get(ENV_DIR)
        os.environ[ENV_DIR] = self.dir

    def tearDown(self):
        if self._env is None:
            os.environ.pop(ENV_DIR, None)
        else:
            os.environ[ENV_DIR] = self._env
        self.tmp.cleanup()


class TestLedgerStore(TempDirCase):
    def test_roundtrip_atomic_and_no_unverified_text(self):
        data = bytes(range(64))
        led = Ledger.for_bytes(data, directory=self.dir)
        added = led.record([
            fact("bytes_at", {"offset": 40, "expected": "28292a2b"}, evidence={"address": {"file_offset": "0x28"}},
                 note="THE LICENSE CHECK IS HERE"),
            fact("bytes_at", {"offset": 8, "expected": "ff"}, verdict=REFUTED, weight=0.0, detail="mismatch",
                 evidence={"actual": "08", "address": {"file_offset": "0x8"}}),
            fact("u32_at", {"offset": 0}, verdict=OBSERVED, weight=0.0,
                 evidence={"actual": "0x3020100", "address": {"file_offset": "0x0"}}),
        ])
        self.assertEqual(added, {"facts": 2, "observed": 1, "refuted": 1})
        path = led.save()
        self.assertTrue(path.exists())
        self.assertEqual(list(path.parent.glob("*.tmp")), [])          # atomic: no temp file left behind
        raw = path.read_text(encoding="utf-8")
        self.assertNotIn("LICENSE CHECK", raw)                          # the model's prose is never stored

        again = Ledger.for_bytes(data, directory=self.dir)              # a fresh process
        self.assertEqual(len(again.facts), 2)
        self.assertEqual(len(again.refuted), 1)
        self.assertEqual(again.observed, {"u32_at@0x0": "0x3020100"})
        self.assertEqual(again.established(), led.established())
        self.assertTrue(again.established()[0].startswith("bytes_at @ 0x28"))
        self.assertTrue(again.known_false()[0].startswith("bytes_at @ 0x8"))

    def test_keyed_by_content_not_by_path(self):
        data = bytes(range(64))
        a = Ledger.for_bytes(data, directory=self.dir, file_path="copy-a.bin")
        a.record([fact("bytes_at", {"offset": 40, "expected": "28"})])
        a.save()
        b = Ledger.for_bytes(data, directory=self.dir, file_path="copy-b.bin")
        self.assertEqual(len(b.facts), 1)                               # same bytes -> same ledger
        self.assertEqual(b.paths, ["copy-a.bin", "copy-b.bin"])
        c = Ledger.for_bytes(data + b"\x00", directory=self.dir)
        self.assertEqual(c.facts, [])                                   # different bytes -> different ledger

    def test_dedup_and_weight_upgrade(self):
        led = Ledger.for_bytes(b"x" * 64, persist=False)
        led.record([fact("bytes_at", {"offset": 1, "expected": "78"}, weight=0.2)])
        led.record([fact("bytes_at", {"offset": 1, "expected": "78"}, weight=0.9)])
        self.assertEqual(len(led.facts), 1)
        self.assertEqual(led.facts[0]["weight"], 0.9)
        led.record([fact("bytes_at", {"offset": 1, "expected": "ff"}, verdict=REFUTED, weight=0.0)])
        led.record([fact("bytes_at", {"offset": 1, "expected": "ff"}, verdict=REFUTED, weight=0.0)])
        self.assertEqual(len(led.refuted), 1)

    def test_tiers_and_pinned_anchors(self):
        led = Ledger.for_bytes(b"x" * 64, persist=False)
        led.record([fact("prove_equiv", {"a": "x0", "b": "x0 + 0"}, weight=1.0)])   # oldest, proof-grade
        for i in range(10):
            led.record([fact("bytes_at", {"offset": i, "expected": "00"}, weight=0.1)])
        view = led.established(max_facts=3)
        self.assertEqual(len(view), 3)
        self.assertTrue(view[0].startswith("prove_equiv"))              # pinned although it is the oldest
        self.assertEqual(led.facts[0]["tier"], PROVEN)
        self.assertEqual(tier_of(fact("behavior_equiv", {"offset": 0, "expr": "x0"}, weight=0.9)), TESTED)
        self.assertIsNone(tier_of(fact("bytes_at", {"offset": 0}, weight=0.0)))     # trivial is not a fact
        self.assertIsNone(tier_of(fact("bytes_at", {"offset": 0}, verdict="INCONCLUSIVE")))

    def test_corrupt_file_is_quarantined_not_fatal(self):
        data = bytes(range(64))
        led = Ledger.for_bytes(data, directory=self.dir)
        led.path.parent.mkdir(parents=True, exist_ok=True)
        led.path.write_text("{not json", encoding="utf-8")
        again = Ledger.for_bytes(data, directory=self.dir)
        self.assertEqual(again.facts, [])
        self.assertIsNotNone(again.load_error)
        self.assertTrue(list(led.path.parent.glob("*.corrupt.json")))
        self.assertIn("load_error", again.summary())

    def test_env_dir_and_clear(self):
        self.assertEqual(ledger_dir(), Path(self.dir) / "ledger")
        led = Ledger.for_bytes(b"y" * 64)                               # no directory: falls back to the env var
        led.record([fact("bytes_at", {"offset": 1, "expected": "79"})])
        led.save()
        self.assertTrue(led.path.exists())
        self.assertTrue(str(led.path).startswith(self.dir))
        led.clear()
        self.assertFalse(led.path.exists())
        self.assertEqual(Ledger.for_bytes(b"y" * 64).facts, [])


class TestAgentRollover(TempDirCase):
    def _run1(self, data):
        p1 = SeqProposer([json.dumps([
            {"kind": "bytes_at", "params": {"offset": 40, "expected": data[40:48].hex()}},                 # verified
            {"kind": "bytes_at", "params": {"offset": 100, "expected": "ffffffffffffffff"},
             "note": "the license check is here"},                                                          # refuted
            {"kind": "u32_at", "params": {"offset": 60}, "observe": True},                                  # observed
        ])])
        return ReconstructionAgent(data, p1, max_rounds=1, min_information=5.0, ledger=self.dir, session="s1").run("goal A")

    def test_resume_is_lossless_and_keeps_negative_memory(self):
        data = bytes(range(256))
        r1 = self._run1(data)
        self.assertEqual(r1["resumed_facts"], 0)
        self.assertEqual(r1["ledger"]["facts"], 2)
        self.assertEqual(r1["ledger"]["refuted"], 1)
        self.assertTrue(Path(r1["ledger_path"]).exists())

        # A brand-new agent = a cleared context. Same directory, nothing else shared.
        rp = RecordingProposer([json.dumps([
            {"kind": "bytes_at", "params": {"offset": 40, "expected": data[40:48].hex()}},                 # restates
        ])])
        r2 = ReconstructionAgent(data, rp, max_rounds=1, min_information=1.0, ledger=self.dir, session="s2").run("goal B")
        self.assertEqual(r2["resumed_facts"], 2)
        prompt = rp.prompts[0]
        self.assertIn("ESTABLISHED", prompt)
        self.assertIn("bytes_at @ 0x28", prompt)                        # the verified fact came back
        self.assertIn("KNOWN FALSE", prompt)
        self.assertIn("bytes_at @ 0x64", prompt)                        # ...and so did the refutation
        self.assertNotIn("license check", prompt)                       # ...but never the model's prose
        self.assertIn('"u32_at@0x3c"', prompt)                          # observed value restored verbatim
        # Restating what the ledger holds says nothing new: flagged, weight 0, not grounded.
        self.assertEqual(r2["history"][0]["known"], 1)
        self.assertTrue(r2["history"][0]["report"]["results"][0]["known"])
        self.assertEqual(r2["history"][0]["report"]["results"][0]["weight"], 0.0)
        self.assertFalse(r2["grounded"])
        self.assertEqual(r2["ledger"]["facts"], 2)                      # no duplicate entry
        self.assertEqual(r2["ledger"]["runs"], 2)
        self.assertEqual(Ledger.for_bytes(data, directory=self.dir).goals, ["goal A", "goal B"])

    def test_fresh_start_discards_the_ledger(self):
        data = bytes(range(256))
        self._run1(data)
        p = SeqProposer([json.dumps([{"kind": "bytes_at", "params": {"offset": 200, "expected": data[200:208].hex()}}])])
        r = ReconstructionAgent(data, p, max_rounds=1, ledger=self.dir, resume=False).run("again")
        self.assertEqual(r["resumed_facts"], 0)
        self.assertEqual(r["ledger"]["facts"], 1)
        self.assertEqual(r["ledger"]["refuted"], 0)

    def test_checkpoint_lands_every_round_even_if_the_model_dies(self):
        data = bytes(range(256))

        class DiesOnRound2:
            calls = 0

            def __call__(self, prompt):
                self.calls += 1
                if self.calls == 2:
                    raise RuntimeError("model endpoint gone")
                return json.dumps([{"kind": "bytes_at", "params": {"offset": 40, "expected": data[40:48].hex()}}])

        with self.assertRaises(RuntimeError):
            ReconstructionAgent(data, DiesOnRound2(), max_rounds=3, min_information=5.0, ledger=self.dir).run("x")
        led = Ledger.for_bytes(data, directory=self.dir)
        self.assertEqual(len(led.facts), 1)                             # round 1 survived the crash

    def test_memory_only_by_default(self):
        data = bytes(range(64))
        r = ReconstructionAgent(data, demo_proposer(data), max_rounds=1).run("demo")
        self.assertIsNone(r["ledger_path"])
        self.assertTrue(r["grounded"])
        self.assertEqual(r["ledger"]["facts"], 2)                       # the API is the same in memory


class TestPromptBudget(unittest.TestCase):
    def test_ladder_trims_the_view_only(self):
        facts = {
            "size": 1,
            "imports": {f"lib{i}.dll": [f"Func{j}" for j in range(40)] for i in range(100)},
            "top_strings": [f"string-{i}-" * 8 for i in range(20)],
            "exports": [f"Export{i}" for i in range(40)],
            "observed": {f"u32_at@{hex(i)}": i for i in range(50)},
            "sections": [],
        }
        full = len(build_prompt("g", facts))
        view, steps, size = compact_facts(facts, budget=20000, goal="g")
        self.assertLessEqual(size, 20000)
        self.assertLess(size, full)
        self.assertTrue(steps)
        self.assertIn("imports_note", view)
        self.assertEqual(len(facts["imports"]), 100)                    # the real sheet is untouched
        self.assertEqual(len(facts["observed"]), 50)
        # Everything the model needs to recover a trimmed item is still there.
        self.assertIn("import_present", view["imports_note"])

    def test_no_op_under_budget(self):
        facts = binary_facts(bytes(range(64)))
        view, steps, size = compact_facts(facts, budget=10 ** 6)
        self.assertEqual(steps, [])
        self.assertEqual(view, facts)

    def test_agent_reports_budget_pressure_and_still_works(self):
        data = bytes(range(64))
        r = ReconstructionAgent(data, demo_proposer(data), max_rounds=1, prompt_budget=2000).run("demo")
        self.assertTrue(r["over_budget"])                               # rules + help alone exceed 2000 chars
        self.assertTrue(r["grounded"])                                  # ...and the loop still does its job
        self.assertIn("prompt_chars", r["history"][0])

    @unittest.skipUnless(os.path.exists(r"C:\Windows\System32\kernel32.dll"), "needs a real PE with many imports")
    def test_scoring_uses_the_full_sheet_not_the_trimmed_view(self):
        with open(r"C:\Windows\System32\kernel32.dll", "rb") as f:
            data = f.read()
        facts = binary_facts(data)
        view, steps, _ = compact_facts(facts, budget=8000)
        self.assertTrue(steps)
        hidden = None
        for lib, funcs in facts["imports"].items():
            shown = set(view["imports"].get(lib, []))
            for fn in funcs:
                if fn not in shown:
                    hidden = fn
                    break
            if hidden:
                break
        self.assertIsNotNone(hidden)
        rp = RecordingProposer([json.dumps([{"kind": "import_present", "params": {"function": hidden}}])])
        r = ReconstructionAgent(data, rp, max_rounds=1, prompt_budget=8000).run("x")
        self.assertNotIn(hidden, rp.prompts[0])                         # hidden from the model...
        res = r["history"][0]["report"]["results"][0]
        self.assertEqual(res["verdict"], VERIFIED)
        self.assertEqual(res["weight"], 0.0)                            # ...yet restating it earns nothing
        self.assertTrue(res["trivial"])


class TestMcpLedger(TempDirCase):
    def setUp(self):
        super().setUp()
        self.data = bytes(range(128))
        self.bin = os.path.join(self.dir, "target.bin")
        with open(self.bin, "wb") as f:
            f.write(self.data)

    def test_verify_records_then_ledger_restores(self):
        res = json.loads(mcp_server.handle_tool_call("re_verify_claim", {"file_path": self.bin, "claims": [
            {"kind": "bytes_at", "params": {"offset": 40, "expected": self.data[40:48].hex()}},
            {"kind": "bytes_at", "params": {"offset": 8, "expected": "ffff"}, "note": "guess"},
        ], "goal": "map the header"}))
        self.assertEqual(res["ledger"]["facts"], 1)
        self.assertEqual(res["ledger"]["refuted"], 1)
        self.assertTrue(res["ledger"]["path"].startswith(self.dir))

        show = json.loads(mcp_server.handle_tool_call("re_ledger", {"file_path": self.bin}))
        self.assertEqual(len(show["established"]), 1)
        self.assertEqual(len(show["known_false"]), 1)
        self.assertIn("KNOWN FALSE", show["context"])
        self.assertIn("map the header", show["context"])
        self.assertNotIn("guess", show["context"])

        # Re-verifying a known fact after a "reset": still VERIFIED, but flagged and weightless.
        res2 = json.loads(mcp_server.handle_tool_call("re_verify_claim", {"file_path": self.bin, "claims": [
            {"kind": "bytes_at", "params": {"offset": 40, "expected": self.data[40:48].hex()}}]}))
        self.assertEqual(res2["results"][0]["verdict"], VERIFIED)
        self.assertTrue(res2["results"][0]["known"])
        self.assertEqual(res2["results"][0]["weight"], 0.0)
        self.assertEqual(res2["ledger"]["facts"], 1)

        idx = json.loads(mcp_server.handle_tool_call("re_ledger", {"file_path": self.bin, "action": "index"}))
        self.assertIn("1 grounded facts", idx["index"])
        cleared = json.loads(mcp_server.handle_tool_call("re_ledger", {"file_path": self.bin, "action": "clear"}))
        self.assertTrue(cleared["cleared"])
        self.assertEqual(json.loads(mcp_server.handle_tool_call("re_ledger", {"file_path": self.bin}))["established"], [])

    def test_record_false_writes_nothing(self):
        res = json.loads(mcp_server.handle_tool_call("re_verify_claim", {"file_path": self.bin, "record": False, "claims": [
            {"kind": "bytes_at", "params": {"offset": 40, "expected": self.data[40:48].hex()}}]}))
        self.assertIsNone(res["ledger"]["path"])
        self.assertEqual(list_ledgers(), [])

    def test_protocol_instructions_resources_and_notifications(self):
        mcp_server.handle_tool_call("re_verify_claim", {"file_path": self.bin, "claims": [
            {"kind": "bytes_at", "params": {"offset": 40, "expected": self.data[40:48].hex()}}]})
        names = [t["name"] for t in mcp_server.TOOLS_MANIFEST]
        self.assertIn("re_ledger", names)
        init = mcp_server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        self.assertIn("re_ledger", init["result"]["instructions"])
        self.assertIn("resources", init["result"]["capabilities"])
        self.assertIsNone(mcp_server.handle_request({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        listed = mcp_server.handle_request({"jsonrpc": "2.0", "id": 2, "method": "resources/list"})["result"]["resources"]
        self.assertEqual(len(listed), 1)
        self.assertTrue(listed[0]["uri"].startswith("reverify://ledger/"))
        read = mcp_server.handle_request({"jsonrpc": "2.0", "id": 3, "method": "resources/read", "params": {"uri": listed[0]["uri"]}})
        self.assertIn("ESTABLISHED", read["result"]["contents"][0]["text"])
        missing = mcp_server.handle_request({"jsonrpc": "2.0", "id": 4, "method": "resources/read", "params": {"uri": "reverify://ledger/nope"}})
        self.assertIn("error", missing)
        # end-to-end over stdio
        lines = "\n".join(json.dumps(m) for m in [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "ping"},
        ]) + "\n"
        old_in, buf = sys.stdin, io.StringIO()
        try:
            sys.stdin = io.StringIO(lines)
            with contextlib.redirect_stdout(buf):
                mcp_server.run_mcp_server()
        finally:
            sys.stdin = old_in
        out = [json.loads(l) for l in buf.getvalue().splitlines() if l.strip()]
        self.assertEqual([o["id"] for o in out], [1, 2])               # the notification got no reply


class TestCliLedger(TempDirCase):
    last_output = ""

    def _main(self, argv):
        old = sys.argv
        buf = io.StringIO()
        try:
            sys.argv = ["reverify"] + argv
            with contextlib.redirect_stdout(buf):
                cli.main()
        finally:
            sys.argv = old
            self.last_output = buf.getvalue()
        return buf.getvalue()

    def test_context_is_a_lazy_index_and_hook_is_ready_to_paste(self):
        self.assertEqual(self._main(["ledger", "--context"]), "")       # nothing grounded -> inject nothing
        data = bytes(range(128))
        led = Ledger.for_bytes(data, file_path="target.bin")
        led.record([fact("bytes_at", {"offset": 40, "expected": "28"}, evidence={"address": {"file_offset": "0x28"}})])
        led.save()
        out = self._main(["ledger", "--context"])
        self.assertEqual(out.count("\n"), 1)                            # one line per binary
        self.assertIn("1 grounded facts", out)
        self.assertNotIn("bytes_at @ 0x28", out)                        # facts are pulled on demand
        full = self._main(["ledger", "--context", "--full"])
        self.assertIn("bytes_at @ 0x28", full)
        hook = json.loads(self._main(["ledger", "--hook"]))
        entry = hook["hooks"]["SessionStart"][0]
        self.assertEqual(entry["matcher"], "compact|clear|resume")
        self.assertIn("reverify ledger --context", entry["hooks"][0]["command"])
        listing = self._main(["ledger"])
        self.assertIn("target.bin", listing)

    def test_reconstruct_mock_checkpoints_to_the_ledger_and_resumes(self):
        data = bytes(range(128))
        target = os.path.join(self.dir, "t.bin")
        with open(target, "wb") as f:
            f.write(data)
        out = self._main(["reconstruct", target, "--goal", "demo", "--mock", "--ledger", self.dir])
        self.assertIn("GROUNDED", out)
        self.assertIn("Ledger:", out)
        self.assertTrue(list((Path(self.dir) / "ledger").glob("*.json")))
        # second run resumes; the demo proposer only restates -> known, weight 0, not grounded -> exit 2
        with self.assertRaises(SystemExit) as cm:
            self._main(["reconstruct", target, "--goal", "demo", "--mock", "--ledger", self.dir])
        self.assertEqual(cm.exception.code, 2)
        self.assertIn("Resumed 2 grounded facts", self.last_output)
        self.assertIn("known 1", self.last_output)
        # --fresh discards the ledger and grounds again from scratch
        out = self._main(["reconstruct", target, "--goal", "demo", "--mock", "--ledger", self.dir, "--fresh"])
        self.assertIn("GROUNDED", out)
        self.assertNotIn("Resumed", out)


if __name__ == "__main__":
    unittest.main()
