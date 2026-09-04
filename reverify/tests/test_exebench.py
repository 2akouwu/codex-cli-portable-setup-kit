"""Tests for the ExeBench / re-executability adapter (reverify/exebench.py).

The adapter compiles a candidate C program and re-runs it against recorded I/O
pairs. It runs native code, so it is off unless REVERIFY_ALLOW_NATIVE_EXEC=1;
the real-compiler tests opt in explicitly and are gated on a C compiler being
present (skipped otherwise); the gate, compile-failure and record-normalization
paths are compiler-independent.
"""

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

pkg_dir = Path(__file__).resolve().parent.parent       # .../reverify
repo_root = pkg_dir.parent                              # .../reverify-main
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from reverify.exebench import (  # noqa: E402
    ExeBenchRecord,
    NATIVE_EXEC_ENV,
    compile_candidate,
    exebench_verify,
    has_compiler,
)
from reverify.verifier import Verifier, Claim, VERIFIED, REFUTED, INCONCLUSIVE  # noqa: E402
from reverify.ledger import Ledger, TESTED  # noqa: E402

HAS_CC = has_compiler("gcc")
ALLOW = {NATIVE_EXEC_ENV: "1"}

# Candidate C under the adapter's I/O contract: inputs via argv, one int on stdout.
C_ADD = '#include <stdlib.h>\n#include <stdio.h>\nint main(int c,char**v){printf("%d",atoi(v[1])+atoi(v[2]));return 0;}'
C_SUB = '#include <stdlib.h>\n#include <stdio.h>\nint main(int c,char**v){printf("%d",atoi(v[1])-atoi(v[2]));return 0;}'
C_BAD = "this is not valid C at all"

ADD_REC = {
    "name": "add",
    "test_cases": [
        {"input": [2, 3], "expected": 5},
        {"input": [7, 8], "expected": 15},
        {"input": [0, 0], "expected": 0},
    ],
}
# same cases expressed as bare [input, expected] pairs, single-int inputs, str expected
ADD_REC_ALT = {
    "name": "add",
    "test_cases": [
        [[2, 3], 5],
        [[7, 8], "15"],
        [[0, 0], 0],
    ],
}


class TestRecordNormalization(unittest.TestCase):
    def test_dict_form(self):
        rec = ExeBenchRecord(ADD_REC)
        self.assertEqual(rec["name"], "add")
        self.assertEqual(len(rec["test_cases"]), 3)
        self.assertEqual(rec["test_cases"][0], {"input": [2, 3], "expected": 5})

    def test_pair_and_string_form(self):
        rec = ExeBenchRecord(ADD_REC_ALT)
        self.assertEqual(rec["test_cases"][1]["expected"], 15)  # "15" -> 15

    def test_malformed_raises(self):
        with self.assertRaises(ValueError):
            ExeBenchRecord({"test_cases": [{"input": [1, 2]}]})  # missing expected
        with self.assertRaises(ValueError):
            ExeBenchRecord({"test_cases": [[1, 2, 3]]})  # pair must be length 2


class TestNativeExecGate(unittest.TestCase):
    """Native execution is opt-in: without the environment flag nothing is compiled or run."""

    def test_off_by_default_is_inconclusive(self):
        with mock.patch.dict(os.environ, {NATIVE_EXEC_ENV: ""}):
            res = exebench_verify(ADD_REC, C_ADD)
            self.assertEqual(res["status"], "inconclusive")
            self.assertIn(NATIVE_EXEC_ENV, res["detail"])
            r = Verifier(b"").verify(Claim("exebench", {"record": ADD_REC, "c_source": C_ADD}))
            self.assertEqual(r["verdict"], INCONCLUSIVE)
            self.assertIn(NATIVE_EXEC_ENV, r["detail"])

    def test_missing_compiler_is_inconclusive_even_when_allowed(self):
        with mock.patch.dict(os.environ, ALLOW):
            res = exebench_verify(ADD_REC, C_ADD, cc="definitely-not-a-compiler")
            self.assertEqual(res["status"], "inconclusive")
            self.assertIn("compiler", res["detail"].lower())

    def test_empty_record_is_inconclusive(self):
        res = exebench_verify({"name": "x", "test_cases": []}, C_ADD, cc="definitely-not-a-compiler")
        self.assertEqual(res["status"], "inconclusive")


@unittest.skipUnless(HAS_CC, "no gcc")
class TestExeBenchVerify(unittest.TestCase):
    def setUp(self):
        self._env = mock.patch.dict(os.environ, ALLOW)
        self._env.start()

    def tearDown(self):
        self._env.stop()

    def test_correct_candidate_passes(self):
        res = exebench_verify(ADD_REC, C_ADD)
        self.assertEqual(res["status"], "pass", res["detail"])
        self.assertEqual(res["passed"], 3)
        self.assertEqual(res["total"], 3)

    def test_wrong_candidate_refutes_with_witness(self):
        res = exebench_verify(ADD_REC, C_SUB)
        self.assertEqual(res["status"], "fail")
        self.assertTrue(res["failures"])
        # first failing case: 2 - 3 = -1, expected 5
        self.assertEqual(res["failures"][0]["expected"], 5)
        self.assertEqual(res["failures"][0]["got"], -1)

    def test_bad_source_does_not_compile(self):
        res = exebench_verify(ADD_REC, C_BAD)
        self.assertEqual(res["status"], "inconclusive")

    def test_pass_is_verified_tested_tier(self):
        r = Verifier(b"").verify(Claim("exebench", {"record": ADD_REC, "c_source": C_ADD}))
        self.assertEqual(r["verdict"], VERIFIED)
        self.assertEqual(r["evidence"]["passed"], 3)
        self.assertTrue(r["evidence"]["native_execution"])
        rep = Verifier(b"").verify_all([Claim("exebench", {"record": ADD_REC, "c_source": C_ADD})])
        self.assertGreater(rep["results"][0]["weight"], 0)
        led = Ledger.for_bytes(b"", persist=False)
        led.record(rep)
        self.assertEqual(led.facts[0]["tier"], TESTED)

    def test_fail_is_refuted_with_cases(self):
        r = Verifier(b"").verify(Claim("exebench", {"record": ADD_REC, "c_source": C_SUB}))
        self.assertEqual(r["verdict"], REFUTED)
        self.assertIn("failing_cases", r["evidence"])

    def test_compile_returns_executable_path_and_cleans_up(self):
        path = compile_candidate(C_ADD)
        self.assertIsNotNone(path)
        self.assertIsNone(compile_candidate(C_BAD))


class TestClaimKind(unittest.TestCase):
    def test_kind_supported(self):
        self.assertIn("exebench", Verifier(b"").SUPPORTED)

    def test_missing_c_source_is_inconclusive(self):
        # verify() catches the ClaimError (like every other kind) and degrades
        # to INCONCLUSIVE with a "malformed claim" detail — it does not raise.
        r = Verifier(b"").verify(Claim("exebench", {"record": ADD_REC}))
        self.assertEqual(r["verdict"], INCONCLUSIVE)
        self.assertIn("malformed", r["detail"])


if __name__ == "__main__":
    unittest.main()
