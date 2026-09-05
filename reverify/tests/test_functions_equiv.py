"""functions_equiv: do two implementations compute the same thing? (verified coding, domain 2)

The Python runner needs no toolchain, so its integration runs on every platform; the C runner
is compiler-gated. Both check: an equivalent implementation VERIFIES, a subtly-wrong one is
REFUTED with a witness (the input and both outputs).
"""

import os
import shutil
import sys
import unittest
from pathlib import Path

tools_root = Path(__file__).resolve().parent.parent
if str(tools_root) not in sys.path:
    sys.path.insert(0, str(tools_root))

from exebench import functions_equiv_verify, NATIVE_EXEC_ENV, normalize_lang  # noqa: E402
from verifier import Verifier, Claim, VERIFIED, REFUTED, INCONCLUSIVE  # noqa: E402

HDR = "#include <stdio.h>\n#include <stdlib.h>\n"
REF_ADD_C = HDR + "int main(int c,char**v){long a=atol(v[1]),b=atol(v[2]);printf(\"%ld\",a+b);return 0;}"
CAND_ADD_C = HDR + "int main(int c,char**v){long a=atol(v[1]),b=atol(v[2]);printf(\"%ld\",b+a);return 0;}"
CAND_SUB_C = HDR + "int main(int c,char**v){long a=atol(v[1]),b=atol(v[2]);printf(\"%ld\",a-b);return 0;}"

REF_ADD_PY = "import sys\na, b = int(sys.argv[1]), int(sys.argv[2])\nprint(a + b)"
CAND_ADD_PY = "import sys\na, b = int(sys.argv[1]), int(sys.argv[2])\nprint(b + a)"   # commutative: equivalent
CAND_SUB_PY = "import sys\na, b = int(sys.argv[1]), int(sys.argv[2])\nprint(a - b)"   # wrong

COMPILER = next((c for c in ("cc", "gcc", "clang") if shutil.which(c)), None)


class TestGatingAndClaim(unittest.TestCase):
    def setUp(self):
        self._env = os.environ.pop(NATIVE_EXEC_ENV, None)

    def tearDown(self):
        if self._env is not None:
            os.environ[NATIVE_EXEC_ENV] = self._env

    def test_off_by_default_is_inconclusive(self):
        r = functions_equiv_verify(CAND_ADD_PY, reference=REF_ADD_PY, lang="python")
        self.assertEqual(r["status"], "inconclusive")
        self.assertIn("off by default", r["detail"])

    def test_needs_reference_or_record(self):
        r = functions_equiv_verify(CAND_ADD_PY, lang="python")
        self.assertEqual(r["status"], "inconclusive")
        self.assertIn("reference", r["detail"])

    def test_unknown_lang(self):
        r = functions_equiv_verify(CAND_ADD_PY, reference=REF_ADD_PY, lang="rust")
        self.assertEqual(r["status"], "inconclusive")
        self.assertIn("unknown lang", r["detail"])
        self.assertIsNone(normalize_lang("rust"))
        self.assertEqual(normalize_lang("Py"), "python")

    def test_claim_missing_candidate_is_malformed(self):
        v = Verifier(b"\x00")
        res = v.verify(Claim.from_dict({"kind": "functions_equiv", "params": {"reference": REF_ADD_PY, "lang": "python"}}))
        self.assertEqual(res["verdict"], INCONCLUSIVE)
        self.assertIn("malformed", res["detail"])

    def test_functions_equiv_is_a_supported_kind(self):
        self.assertIn("functions_equiv", Verifier.SUPPORTED)


class TestPythonRunner(unittest.TestCase):
    """No toolchain needed — runs on every platform, so this is real CI coverage."""

    def setUp(self):
        os.environ[NATIVE_EXEC_ENV] = "1"

    def tearDown(self):
        os.environ.pop(NATIVE_EXEC_ENV, None)

    def test_equivalent_python_passes(self):
        r = functions_equiv_verify(CAND_ADD_PY, reference=REF_ADD_PY, lang="python")
        self.assertEqual(r["status"], "pass", r["detail"])
        self.assertGreaterEqual(r["passed"], 8)

    def test_wrong_python_is_refuted_with_witness(self):
        r = functions_equiv_verify(CAND_SUB_PY, reference=REF_ADD_PY, lang="python")
        self.assertEqual(r["status"], "fail")
        w = r["failures"][0]
        self.assertEqual(set(w), {"input", "reference", "candidate"})
        self.assertNotEqual(w["reference"], w["candidate"])

    def test_syntax_error_candidate_is_inconclusive(self):
        r = functions_equiv_verify("def (:::", reference=REF_ADD_PY, lang="python")
        self.assertEqual(r["status"], "inconclusive")
        self.assertIn("did not build", r["detail"])

    def test_through_the_verifier_python(self):
        v = Verifier(b"\x00")
        ok = v.verify(Claim.from_dict({"kind": "functions_equiv",
                                       "params": {"candidate": CAND_ADD_PY, "reference": REF_ADD_PY, "lang": "python"}}))
        self.assertEqual(ok["verdict"], VERIFIED)
        self.assertEqual(ok["evidence"]["lang"], "python")
        bad = v.verify(Claim.from_dict({"kind": "functions_equiv",
                                        "params": {"candidate": CAND_SUB_PY, "reference": REF_ADD_PY, "lang": "python"}}))
        self.assertEqual(bad["verdict"], REFUTED)
        self.assertIn("failing_cases", bad["evidence"])


@unittest.skipUnless(COMPILER, "no C compiler on PATH")
class TestCRunner(unittest.TestCase):
    def setUp(self):
        os.environ[NATIVE_EXEC_ENV] = "1"

    def tearDown(self):
        os.environ.pop(NATIVE_EXEC_ENV, None)

    def test_equivalent_c_passes(self):
        r = functions_equiv_verify(CAND_ADD_C, reference=REF_ADD_C, lang="c", cc=COMPILER)
        self.assertEqual(r["status"], "pass", r["detail"])

    def test_wrong_c_is_refuted(self):
        r = functions_equiv_verify(CAND_SUB_C, reference=REF_ADD_C, lang="c", cc=COMPILER)
        self.assertEqual(r["status"], "fail")
        self.assertTrue(r["failures"])


if __name__ == "__main__":
    unittest.main()
