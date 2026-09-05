"""The reconstruction re-executability corpus: a correct rebuild verifies, a wrong one is refuted.

The Python-lang gate runs on every platform (no toolchain), so it is real CI coverage of the
re-executability metric and the zero-false-accept property; the C-lang gate is compiler-gated.
"""

import os
import shutil
import sys
import unittest
from pathlib import Path

repo_root = Path(__file__).resolve().parent.parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from benchmarks import reconstructions as rc  # noqa: E402
from benchmarks import build_reconstructions as br  # noqa: E402

COMPILER = next((c for c in ("cc", "gcc", "clang") if shutil.which(c)), None)


class TestCorpus(unittest.TestCase):
    def test_wellformed(self):
        records = rc.load()
        self.assertGreaterEqual(len(records), 12)
        for r in records:
            self.assertIn("c", r["reference"])
            self.assertIn("python", r["reference"])
            labels = sorted(c["label"] for c in r["candidates"])
            self.assertEqual(labels, ["correct", "wrong"])
            for cand in r["candidates"]:
                self.assertTrue(cand["c"].strip() and cand["python"].strip())

    def test_corpus_is_up_to_date_with_the_builder(self):
        # regenerating must produce the committed file byte-for-byte (deterministic corpus)
        path = Path(rc.CORPUS)
        before = path.read_text(encoding="utf-8")
        br.build()
        after = path.read_text(encoding="utf-8")
        self.assertEqual(before, after)


class TestPythonGate(unittest.TestCase):
    """Runs everywhere — the re-executability metric without a compiler."""

    def setUp(self):
        self._env = os.environ.get("REVERIFY_ALLOW_NATIVE_EXEC")
        os.environ["REVERIFY_ALLOW_NATIVE_EXEC"] = "1"

    def tearDown(self):
        if self._env is None:
            os.environ.pop("REVERIFY_ALLOW_NATIVE_EXEC", None)
        else:
            os.environ["REVERIFY_ALLOW_NATIVE_EXEC"] = self._env

    def test_correct_reexecute_wrong_refuted_zero_false_accepts(self):
        records = rc.load()
        n_correct = sum(1 for r in records for c in r["candidates"] if c["label"] == "correct")
        n_wrong = sum(1 for r in records for c in r["candidates"] if c["label"] == "wrong")
        s = rc.score(records, "python")   # curated asymmetric inputs distinguish every wrong rebuild
        self.assertEqual(s["false_accepts"], 0, s["false_accept_items"])
        self.assertEqual(s["missed"], 0)
        self.assertEqual(s["inconclusive"], 0)
        self.assertEqual(s["reexecutable"], n_correct)
        self.assertEqual(s["refuted"], n_wrong)

    def test_run_entry_gates_on_false_accepts(self):
        import io
        from contextlib import redirect_stdout
        with redirect_stdout(io.StringIO()):
            self.assertEqual(rc.run(["python"], fail_on_false_accept=True), 0)


@unittest.skipUnless(COMPILER, "no C compiler on PATH")
class TestCGate(unittest.TestCase):
    def setUp(self):
        os.environ["REVERIFY_ALLOW_NATIVE_EXEC"] = "1"

    def tearDown(self):
        os.environ.pop("REVERIFY_ALLOW_NATIVE_EXEC", None)

    def test_c_reconstructions_scored_with_zero_false_accepts(self):
        records = rc.load()
        s = rc.score(records, "c", cc=COMPILER)
        self.assertEqual(s["false_accepts"], 0, s["false_accept_items"])
        self.assertEqual(s["missed"], 0)
        self.assertGreaterEqual(s["reexecutable"], 12)
        self.assertGreaterEqual(s["refuted"], 12)


if __name__ == "__main__":
    unittest.main()
