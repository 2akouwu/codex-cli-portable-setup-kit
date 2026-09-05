"""The re-executability scorecard: dataset loading, aggregation, and the false-accept gate.

The aggregation is tested with an injected verifier (no compiler needed); a gated
integration test compiles and runs the bundled sample only when a compiler is
present and native execution is opted in.
"""

import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

tools_root = Path(__file__).resolve().parent.parent
repo_root = tools_root.parent
for p in (str(tools_root), str(repo_root)):
    if p not in sys.path:
        sys.path.insert(0, p)

from benchmarks import reexec_dataset as rd  # noqa: E402

SAMPLE = repo_root / "benchmarks" / "corpus" / "reexec_sample.jsonl"


class TestLoading(unittest.TestCase):
    def test_loads_jsonl_and_array(self):
        recs = [{"name": "a", "candidate_c": "x", "test_cases": []},
                {"name": "b", "c_source": "y", "io_pairs": [[1, 1]]}]
        with tempfile.TemporaryDirectory() as d:
            jl = Path(d) / "a.jsonl"
            jl.write_text("\n".join(json.dumps(r) for r in recs) + "\n", encoding="utf-8")
            self.assertEqual(len(rd.load_dataset(str(jl))), 2)
            arr = Path(d) / "a.json"
            arr.write_text(json.dumps(recs), encoding="utf-8")
            self.assertEqual(len(rd.load_dataset(str(arr))), 2)

    def test_candidate_source_key_aliases(self):
        self.assertEqual(rd.candidate_source({"candidate_c": "A"}), "A")
        self.assertEqual(rd.candidate_source({"c_source": "B"}), "B")
        self.assertEqual(rd.candidate_source({"source": "C"}), "C")
        self.assertIsNone(rd.candidate_source({"name": "x"}))

    def test_sample_dataset_present_and_valid(self):
        recs = rd.load_dataset(str(SAMPLE))
        self.assertEqual(len(recs), 3)
        self.assertTrue(all(rd.candidate_source(r) for r in recs))
        self.assertEqual({r["label"] for r in recs}, {"correct", "wrong"})


class TestScoring(unittest.TestCase):
    def _verify_by_label(self, honest=True):
        # honest verifier: correct -> pass, wrong -> fail; dishonest: wrong -> pass
        def verify(rec, src):
            label = rec.get("label")
            if label == "correct":
                return "pass"
            if label == "wrong":
                return "pass" if not honest else "fail"
            return "inconclusive"
        return verify

    def test_aggregation_and_rates(self):
        recs = [
            {"name": "c1", "candidate_c": "x", "label": "correct"},
            {"name": "c2", "candidate_c": "x", "label": "correct"},
            {"name": "w1", "candidate_c": "x", "label": "wrong"},
            {"name": "u1", "candidate_c": "x"},                    # no label -> inconclusive via verify
            {"name": "n1"},                                        # no source at all
        ]
        s = rd.score_records(recs, verify=self._verify_by_label())
        self.assertEqual(s["total"], 5)
        self.assertEqual(s["reexecutable"], 2)
        self.assertEqual(s["refuted"], 1)
        self.assertEqual(s["no_source"], 1)
        self.assertEqual(s["inconclusive"], 2)                    # u1 (inconclusive) + n1 (no source)
        self.assertEqual(s["labeled"], 3)
        self.assertEqual(s["false_accepts"], 0)
        self.assertEqual(s["missed_correct"], 0)
        self.assertAlmostEqual(s["reexec_rate"], 2 / 3)

    def test_false_accept_is_counted_and_named(self):
        recs = [{"name": "sneaky", "candidate_c": "x", "label": "wrong"}]
        s = rd.score_records(recs, verify=self._verify_by_label(honest=False))
        self.assertEqual(s["false_accepts"], 1)
        self.assertEqual(s["false_accept_items"], ["sneaky"])

    def test_missed_correct_counted(self):
        def verify(rec, src):
            return "fail"                                          # over-strict: refute everything
        s = rd.score_records([{"name": "ok", "candidate_c": "x", "label": "correct"}], verify=verify)
        self.assertEqual(s["missed_correct"], 1)
        self.assertEqual(s["reexecutable"], 0)

    def test_report_mentions_the_gate(self):
        s = rd.score_records([{"name": "w", "candidate_c": "x", "label": "wrong"}],
                             verify=self._verify_by_label())
        report = rd.format_report(s)
        self.assertIn("false accepts", report)
        self.assertIn("MUST be 0", report)


class TestRunEntry(unittest.TestCase):
    def setUp(self):
        self._env = os.environ.get("REVERIFY_ALLOW_NATIVE_EXEC")
        os.environ.pop("REVERIFY_ALLOW_NATIVE_EXEC", None)

    def tearDown(self):
        if self._env is None:
            os.environ.pop("REVERIFY_ALLOW_NATIVE_EXEC", None)
        else:
            os.environ["REVERIFY_ALLOW_NATIVE_EXEC"] = self._env

    def test_run_without_optin_is_inconclusive_and_says_so(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = rd.run(str(SAMPLE))
        text = out.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("native execution is off", text)
        self.assertIn("inconclusive", text)


COMPILER = next((c for c in ("cc", "gcc", "clang") if shutil.which(c)), None)


@unittest.skipUnless(COMPILER, "no C compiler on PATH")
class TestIntegration(unittest.TestCase):
    def setUp(self):
        os.environ["REVERIFY_ALLOW_NATIVE_EXEC"] = "1"

    def tearDown(self):
        os.environ.pop("REVERIFY_ALLOW_NATIVE_EXEC", None)

    def test_correct_pass_wrong_refuted_zero_false_accepts(self):
        recs = rd.load_dataset(str(SAMPLE))
        s = rd.score_records(recs, cc=COMPILER)
        self.assertEqual(s["false_accepts"], 0, s["false_accept_items"])
        self.assertGreaterEqual(s["reexecutable"], 2)             # add_ok, max_ok
        self.assertGreaterEqual(s["refuted"], 1)                  # add_wrong


if __name__ == "__main__":
    unittest.main()
