"""Proof-grade expression equivalence via Z3 (MBA deobfuscation verification)."""

import sys
import unittest
from pathlib import Path

tools_root = Path(__file__).resolve().parent.parent
if str(tools_root) not in sys.path:
    sys.path.insert(0, str(tools_root))

from backends import HAS_Z3
from behavior import prove_expr_equiv
from verifier import Verifier, Claim, verify_claims, VERIFIED, REFUTED, INCONCLUSIVE


@unittest.skipUnless(HAS_Z3, "z3 not installed")
class TestProveExprEquiv(unittest.TestCase):
    def test_commutativity_proven(self):
        r = prove_expr_equiv("x0 + x1", "x1 + x0")
        self.assertEqual(r["status"], "proven")

    def test_mba_identity_proven(self):
        # the classic MBA identity: (x ^ y) + 2*(x & y) == x + y, for all 64-bit inputs
        r = prove_expr_equiv("(x0 ^ x1) + 2*(x0 & x1)", "x0 + x1")
        self.assertEqual(r["status"], "proven")

    def test_xor_is_not_add_refuted_with_counterexample(self):
        r = prove_expr_equiv("x0 ^ x1", "x0 + x1")
        self.assertEqual(r["status"], "refuted")
        self.assertIn("counterexample", r)
        ce = r["counterexample"]
        a = int(ce["x0"], 16); b = int(ce["x1"], 16)
        self.assertNotEqual((a ^ b), (a + b) & 0xFFFFFFFFFFFFFFFF)

    def test_bit_width_matters(self):
        # x*2 vs x<<1 always equal
        self.assertEqual(prove_expr_equiv("x0 * 2", "x0 << 1")["status"], "proven")


@unittest.skipUnless(HAS_Z3, "z3 not installed")
class TestProveClaim(unittest.TestCase):
    def test_claim_proven_has_full_weight(self):
        rep = verify_claims(b"", [{
            "kind": "prove_equiv", "a": "(x0 ^ x1) + 2*(x0 & x1)", "b": "x0 + x1",
        }])
        r = rep["results"][0]
        self.assertEqual(r["verdict"], VERIFIED)
        self.assertIn("proven", r["detail"])
        self.assertEqual(r["weight"], 1.0)

    def test_claim_refuted_carries_counterexample(self):
        r = Verifier(b"").verify(Claim("prove_equiv", {"a": "x0 & x1", "b": "x0 | x1"}))
        self.assertEqual(r["verdict"], REFUTED)
        self.assertIn("counterexample", r["evidence"])

    def test_identity_expressions_weigh_zero(self):
        rep = verify_claims(b"", [{"kind": "prove_equiv", "a": "x0 + x1", "b": "x0 + x1"}])
        r = rep["results"][0]
        self.assertEqual(r["verdict"], VERIFIED)   # trivially true...
        self.assertEqual(r["weight"], 0.0)          # ...but says nothing


class TestProveGating(unittest.TestCase):
    @unittest.skipIf(HAS_Z3, "z3 is installed")
    def test_inconclusive_without_z3(self):
        r = Verifier(b"").verify(Claim("prove_equiv", {"a": "x0", "b": "x0"}))
        self.assertEqual(r["verdict"], INCONCLUSIVE)


if __name__ == "__main__":
    unittest.main()
