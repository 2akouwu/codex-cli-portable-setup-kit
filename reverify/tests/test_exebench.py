"""Tests for the ExeBench / re-executability adapter (reverify/exebench.py).

The adapter compiles a candidate C program and re-runs it against recorded I/O
pairs. The real-compiler tests are gated on a C compiler being present (skipped
otherwise); the gated/compile-failure paths and record normalization are
compiler-independent.
"""

import sys
import unittest
from pathlib import Path

pkg_dir = Path(__file__).resolve().parent.parent       # .../reverify
repo_root = pkg_dir.parent                              # .../reverify-main
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from reverify.exebench import (  # noqa: E402
    ExeBenchRecord,
    compile_candidate,
    exebench_verify,
    has_compiler,
)
from reverify.verifier import Verifier, Claim, VERIFIED, REFUTED, INCONCLUSIVE  # noqa: E402

HAS_CC = has_compiler("gcc")

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


class TestExeBenchVerify(unittest.TestCase):
    @unittest.skipUnless(HAS_CC, "no gcc")
    def test_correct_candidate_passes(self):
        res = exebench_verify(ADD_REC, C_ADD)
        self.assertEqual(res["status"], "pass")
        self.assertEqual(res["passed"], 3)
        self.assertEqual(res["total"], 3)

    @unittest.skipUnless(HAS_CC, "no gcc")
    def test_wrong_candidate_refutes_with_witness(self):
        res = exebench_verify(ADD_REC, C_SUB)
        self.assertEqual(res["status"], "fail")
        self.assertTrue(res["failures"])
        # first failing case: 2 - 3 = -1, expected 5
        self.assertEqual(res["failures"][0]["expected"], 5)
        self.assertEqual(res["failures"][0]["got"], -1)

    @unittest.skipUnless(HAS_CC, "no gcc")
    def test_bad_source_does_not_compile(self):
        res = exebench_verify(ADD_REC, C_BAD)
        self.assertEqual(res["status"], "inconclusive")

    def test_gated_without_compiler(self):
        # A compiler that is definitely absent: the adapter must gate, not fail.
        res = exebench_verify(ADD_REC, C_ADD, cc="definitely-not-a-compiler")
        self.assertEqual(res["status"], "inconclusive")
        self.assertIn("compiler", res["detail"].lower())

    def test_empty_record_is_inconclusive(self):
        res = exebench_verify({"name": "x", "test_cases": []}, C_ADD, cc="definitely-not-a-compiler")
        self.assertEqual(res["status"], "inconclusive")


class TestClaimKind(unittest.TestCase):
    def test_unknown_kind_still_supported(self):
        self.assertIn("exebench", Verifier(b"").SUPPORTED)

    @unittest.skipUnless(HAS_CC, "no gcc")
    def test_pass_is_verified(self):
        r = Verifier(b"").verify(Claim("exebench", {"record": ADD_REC, "c_source": C_ADD}))
        self.assertEqual(r["verdict"], VERIFIED)
        self.assertEqual(r["evidence"]["passed"], 3)

    @unittest.skipUnless(HAS_CC, "no gcc")
    def test_fail_is_refuted_with_cases(self):
        r = Verifier(b"").verify(Claim("exebench", {"record": ADD_REC, "c_source": C_SUB}))
        self.assertEqual(r["verdict"], REFUTED)
        self.assertIn("failing_cases", r["evidence"])

    def test_gate_is_inconclusive(self):
        r = Verifier(b"").verify(Claim("exebench", {"record": ADD_REC, "c_source": C_ADD, "cc": "nope"}))
        self.assertEqual(r["verdict"], INCONCLUSIVE)

    def test_missing_c_source_is_inconclusive(self):
        # verify() catches the ClaimError (like every other kind) and degrades
        # to INCONCLUSIVE with a "malformed claim" detail — it does not raise.
        r = Verifier(b"").verify(Claim("exebench", {"record": ADD_REC}))
        self.assertEqual(r["verdict"], INCONCLUSIVE)
        self.assertIn("malformed", r["detail"])


@unittest.skipUnless(HAS_CC, "no gcc")
class TestCompileHelper(unittest.TestCase):
    def test_compile_returns_executable_path(self):
        path = compile_candidate(C_ADD)
        self.assertIsNotNone(path)

    def test_compile_bad_source_returns_none(self):
        self.assertIsNone(compile_candidate(C_BAD))


if __name__ == "__main__":
    unittest.main()
