"""Rollover controller: fresh context per session, hand-off verified from the ledger.

What must hold: a rollover happens on the model's signal, on the token budget, or on
drift; the next session sees ESTABLISHED and KNOWN FALSE from the ledger only; the
model's own notes travel labelled unverified and never become facts; the checkpoint
persists and resumes.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

tools_root = Path(__file__).resolve().parent.parent
if str(tools_root) not in sys.path:
    sys.path.insert(0, str(tools_root))

from rollover import Orchestrator, MockDriver, Checkpoint, _parse_action, demo_scripts  # noqa: E402
from ledger import ENV_DIR  # noqa: E402
import mcp_server  # noqa: E402

DATA = bytes(range(256))
GOOD = {"kind": "bytes_at", "params": {"offset": 40, "expected": DATA[40:48].hex()}}
BAD = {"kind": "bytes_at", "params": {"offset": 100, "expected": "ffffffffffffffff"}, "note": "the key is here"}


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


class TestParseAction(unittest.TestCase):
    def test_tolerant_parsing(self):
        self.assertEqual(_parse_action('{"done": true}')["done"], True)
        self.assertEqual(_parse_action('Sure!\n```json\n{"rollover": true, "reason": "x"}\n```')["rollover"], True)
        self.assertEqual(len(_parse_action('[{"kind": "bytes_at", "params": {"offset": 0, "expected": "00"}}]')["claims"]), 1)
        self.assertIn("note", _parse_action("I am not sure what to do"))


class TestRollover(TempDirCase):
    def test_model_signal_and_verified_handoff(self):
        driver = MockDriver([
            [
                json.dumps({"claims": [GOOD, BAD],
                            "checkpoint": {"done": ["read the header"], "decisions": ["the key is at 0x64 (my guess)"],
                                           "next_step": "look after the key"}}),
                json.dumps({"rollover": True, "reason": "context feels long"}),
            ],
            [
                json.dumps({"claims": [{"kind": "u32_at", "params": {"offset": 60}, "observe": True}],
                            "checkpoint": {"todo": ["map the tail"]}}),
                json.dumps({"done": True, "summary": "finished"}),
            ],
        ])
        orch = Orchestrator(DATA, driver, directory=self.dir, task_id="t1", session_tokens=100_000)
        res = orch.run("map the header")
        self.assertTrue(res["done"])
        self.assertEqual(res["sessions"], 2)
        self.assertTrue(res["rollovers"][0]["reason"].startswith("model:"))
        # the second session opened fresh: facts from the ledger, the guess labelled unverified
        opening2 = driver.calls[1]["opening"]
        self.assertIn("ESTABLISHED", opening2)
        self.assertIn("bytes_at @ 0x28", opening2)
        self.assertIn("KNOWN FALSE", opening2)
        self.assertIn("bytes_at @ 0x64", opening2)
        self.assertIn("HAND-OFF", opening2)
        self.assertIn("decisions (unverified): the key is at 0x64 (my guess)", opening2)
        est_block = opening2.split("ESTABLISHED", 1)[1].split("KNOWN FALSE", 1)[0]
        self.assertNotIn("my guess", est_block)                   # never promoted to a fact
        self.assertNotIn("the key is here", est_block)            # the claim note never becomes a fact either
        # ledger and checkpoint persisted
        self.assertEqual(res["facts"], 2)                         # verified window + observed value
        self.assertEqual(res["refuted"], 1)
        cp_path = Path(res["checkpoint_path"])
        self.assertTrue(cp_path.exists())
        self.assertEqual(len(list((cp_path.parent / "history").glob("session-*.json"))), 2)
        saved = json.load(open(cp_path, encoding="utf-8"))
        self.assertEqual(saved["sessions"], 2)
        self.assertIn("map the tail", saved["todo"])

    def test_budget_rollover(self):
        driver = MockDriver([
            [json.dumps({"claims": [GOOD]}), json.dumps({"claims": [GOOD]})],
            [json.dumps({"done": True})],
        ])
        res = Orchestrator(DATA, driver, directory=None, session_tokens=200).run("x")   # opening alone exceeds 200 tokens
        self.assertTrue(res["done"])
        self.assertEqual(res["sessions"], 2)
        self.assertTrue(res["rollovers"][0]["reason"].startswith("budget:"))

    def test_drift_rollover(self):
        same = json.dumps({"claims": [GOOD]})
        driver = MockDriver([[same, same, same, same, same], [json.dumps({"done": True})]])
        res = Orchestrator(DATA, driver, directory=None, session_tokens=10**7, drift_window=2, drift_ratio=0.75).run("x")
        self.assertTrue(res["done"])
        self.assertTrue(res["rollovers"][0]["reason"].startswith("drift:"))
        self.assertEqual(res["facts"], 1)                          # restating never adds facts

    def test_turn_cap_and_max_sessions(self):
        driver = MockDriver([[json.dumps({"note": "thinking..."})]])
        res = Orchestrator(DATA, driver, directory=None, max_turns=2, max_sessions=2, session_tokens=10**7).run("x")
        self.assertFalse(res["done"])
        self.assertEqual(res["sessions"], 2)
        self.assertTrue(all(r["reason"].startswith("turn cap") for r in res["rollovers"]))

    def test_resume_checkpoint_in_a_new_orchestrator(self):
        first = MockDriver([[json.dumps({"claims": [GOOD], "checkpoint": {"todo": ["second half"]}}),
                            json.dumps({"rollover": True, "reason": "stop here"})]])
        res1 = Orchestrator(DATA, first, directory=self.dir, task_id="resume", max_sessions=1).run("goal")
        self.assertFalse(res1["done"])
        second = MockDriver([[json.dumps({"done": True})]])
        orch2 = Orchestrator(DATA, second, directory=self.dir, task_id="resume", max_sessions=1)
        res2 = orch2.run("goal")
        self.assertTrue(res2["done"])
        opening = second.calls[0]["opening"]
        self.assertIn("todo: second half", opening)
        self.assertIn("bytes_at @ 0x28", opening)
        self.assertEqual(res2["checkpoint"]["sessions"], 2)

    def test_demo_scripts_finish(self):
        res = Orchestrator(DATA, MockDriver(demo_scripts(DATA)), directory=None).run("demo")
        self.assertTrue(res["done"])
        self.assertEqual(res["sessions"], 2)


class TestMcpCheckpoint(TempDirCase):
    def test_save_then_load(self):
        target = os.path.join(self.dir, "t.bin")
        with open(target, "wb") as f:
            f.write(DATA)
        out = json.loads(mcp_server.handle_tool_call("re_checkpoint", {
            "file_path": target, "action": "save", "task": "demo", "goal": "map it",
            "checkpoint": {"done": ["header"], "decisions": ["guess: key at 0x64"], "next_step": "verify the key"}}))
        self.assertIn("saved", out)
        loaded = json.loads(mcp_server.handle_tool_call("re_checkpoint", {"file_path": target, "action": "load", "task": "demo"}))
        self.assertEqual(loaded["checkpoint"]["done"], ["header"])
        self.assertIn("decisions (unverified): guess: key at 0x64", loaded["handoff"])
        self.assertIn("ledger_index", loaded)
        missing = json.loads(mcp_server.handle_tool_call("re_checkpoint", {"file_path": target, "action": "load", "task": "nope"}))
        self.assertIsNone(missing["checkpoint"])


if __name__ == "__main__":
    unittest.main()
