"""functions_equiv: do two implementations compute the same thing? (verified AI coding, domain 2)

The gating and malformed-claim paths run without a compiler; a compiler-gated
integration test compiles a reference and a candidate and confirms an equivalent
one VERIFIES and a subtly-wrong one is REFUTED with a witness.
"""

import os
import shutil
import sys
import unittest
from pathlib import Path

tools_root = Path(__file__).resolve().parent.parent
if str(tools_root) not in sys.path:
    sys.path.insert(0, str(tools_root))

from exebench import functions_equiv_verify, NATIVE_EXEC_ENV  # noqa: E402
from verifier import Verifier, Claim, VERIFIED, REFUTED, INCONCLUSIVE  # noqa: E402

HDR = "#include <stdio.h>\n#include <stdlib.h>\n"
REF_ADD = HDR + "int main(int c,char**v){long a=atol(v[1]),b=atol(v[2]);printf(\"%ld\",a+b);return 0;}"
CAND_ADD = HDR + "int main(int c,char**v){long a=atol(v[1]),b=atol(v[2]);printf(\"%ld\",b+a);return 0;}"      # commutative: equivalent
CAND_SUB = HDR + "int main(int c,char**v){long a=atol(v[1]),b=atol(v[2]);printf(\"%ld\",a-b);return 0;}"      # wrong

COMPILER = next((c for c in ("cc", "gcc", "clang") if shutil.which(c)), None)


class TestGatingAndClaim(unittest.TestCase):
    def setUp(self):
        self._env = os.environ.pop(NATIVE_EXEC_ENV, None)

    def tearDown(self):
        if self._env is not None:
            os.environ[NATIVE_EXEC_ENV] = self._env

    def test_off_by_default_is_inconclusive(self):
        r = functions_equiv_verify(CAND_ADD, reference_c=REF_ADD)
        self.assertEqual(r["status"], "inconclusive")
        self.assertIn("off by default", r["detail"])

    def test_needs_reference_or_record(self):
        r = functions_equiv_verify(CAND_ADD)
        self.assertEqual(r["status"], "inconclusive")
        self.assertIn("reference", r["detail"])

    def test_record_path_delegates_to_exebench(self):
        # with a record and no reference, it is exactly exebench_verify (inconclusive w/o opt-in)
        r = functions_equiv_verify(CAND_ADD, record={"test_cases": [{"input": [1, 2], "expected": 3}]})
        self.assertEqual(r["status"], "inconclusive")

    def test_claim_missing_candidate_is_malformed(self):
        v = Verifier(b"\x00")
        res = v.verify(Claim.from_dict({"kind": "functions_equiv", "params": {"reference_c": REF_ADD}}))
        self.assertEqual(res["verdict"], INCONCLUSIVE)
        self.assertIn("malformed", res["detail"])

    def test_functions_equiv_is_a_supported_kind(self):
        self.assertIn("functions_equiv", Verifier.SUPPORTED)


@unittest.skipUnless(COMPILER, "no C compiler on PATH")
class TestIntegration(unittest.TestCase):
    def setUp(self):
        os.environ[NATIVE_EXEC_ENV] = "1"

    def tearDown(self):
        os.environ.pop(NATIVE_EXEC_ENV, None)

    def test_equivalent_implementations_pass(self):
        r = functions_equiv_verify(CAND_ADD, reference_c=REF_ADD, cc=COMPILER)
        self.assertEqual(r["status"], "pass", r["detail"])
        self.assertGreaterEqual(r["passed"], 8)

    def test_wrong_implementation_is_refuted_with_witness(self):
        r = functions_equiv_verify(CAND_SUB, reference_c=REF_ADD, cc=COMPILER)
        self.assertEqual(r["status"], "fail")
        self.assertTrue(r["failures"])
        w = r["failures"][0]
        self.assertIn("input", w)
        self.assertIn("reference", w)
        self.assertIn("candidate", w)
        self.assertNotEqual(w["reference"], w["candidate"])

    def test_through_the_verifier_verdicts(self):
        v = Verifier(b"\x00")
        ok = v.verify(Claim.from_dict({"kind": "functions_equiv",
                                       "params": {"candidate_c": CAND_ADD, "reference_c": REF_ADD, "cc": COMPILER}}))
        self.assertEqual(ok["verdict"], VERIFIED)
        bad = v.verify(Claim.from_dict({"kind": "functions_equiv",
                                        "params": {"candidate_c": CAND_SUB, "reference_c": REF_ADD, "cc": COMPILER}}))
        self.assertEqual(bad["verdict"], REFUTED)
        self.assertIn("failing_cases", bad["evidence"])


if __name__ == "__main__":
    unittest.main()
