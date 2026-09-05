"""Behavioral equivalence: verify a reconstruction by running it (execution as judge)."""

import struct
import sys
import unittest
from pathlib import Path

tools_root = Path(__file__).resolve().parent.parent
if str(tools_root) not in sys.path:
    sys.path.insert(0, str(tools_root))

from backends import HAS_UNICORN
from behavior import behavioral_equiv, run_function, eval_expr, gen_inputs, ExprError
from verifier import Verifier, Claim, verify_claims, VERIFIED, REFUTED, INCONCLUSIVE

# x86-64 System V: rax = rdi + rsi ; ret
ADD_FN = bytes.fromhex("4889f8" "4801f0" "c3")
# rax = rdi ^ rsi ; ret   (mov rax,rdi ; xor rax,rsi ; ret)
XOR_FN = bytes.fromhex("4889f8" "4831f0" "c3")
# rax = rdi + rsi via lea (different encoding, same behavior): lea rax,[rdi+rsi] ; ret
ADD_LEA = bytes.fromhex("488d0437" "c3")
# 32-bit x86: eax = edi + esi ; ret   (mov eax,edi ; add eax,esi ; ret)
ADD_FN_32 = bytes.fromhex("89f8" "03c6" "c3")


class TestExprSafety(unittest.TestCase):
    def test_arithmetic(self):
        self.assertEqual(eval_expr("x0 + x1", {"x0": 5, "x1": 3}), 8)
        self.assertEqual(eval_expr("x0 ^ x1", {"x0": 0xF0, "x1": 0x0F}), 0xFF)
        self.assertEqual(eval_expr("(x0 << 2) | 1", {"x0": 1}), 5)

    def test_rejects_calls_and_attributes(self):
        for bad in ("__import__('os')", "x0.__class__", "open('f')", "x0 if x0 else x1"):
            with self.assertRaises(ExprError):
                eval_expr(bad, {"x0": 1, "x1": 2})


@unittest.skipUnless(HAS_UNICORN, "unicorn not installed")
class TestRunFunction(unittest.TestCase):
    def test_add_function_over_inputs(self):
        for a, b in [(1, 1), (5, 3), (0xFFFFFFFFFFFFFFFF, 1), (100, 200)]:
            self.assertEqual(run_function(ADD_FN, (a, b)), (a + b) & 0xFFFFFFFFFFFFFFFF)

    def test_garbage_returns_none(self):
        self.assertIsNone(run_function(bytes.fromhex("ffffffffff"), (1, 2)))


@unittest.skipUnless(HAS_UNICORN, "unicorn not installed")
class TestBehavioralEquiv(unittest.TestCase):
    def test_expr_matches(self):
        r = behavioral_equiv(ADD_FN, expr="x0 + x1", nargs=2)
        self.assertEqual(r["status"], "equivalent")
        self.assertGreaterEqual(r["tested"], 8)

    def test_expr_mismatch_has_counterexample(self):
        r = behavioral_equiv(ADD_FN, expr="x0 ^ x1", nargs=2)
        self.assertEqual(r["status"], "refuted")
        self.assertIn("counterexample", r)
        ce = r["counterexample"]
        # the witness must really distinguish add from xor
        a = int(ce["input"][0], 16); b = int(ce["input"][1], 16)
        self.assertNotEqual((a + b) & 0xFFFFFFFFFFFFFFFF, a ^ b)

    def test_candidate_code_different_encoding_same_behavior(self):
        r = behavioral_equiv(ADD_FN, candidate_code=ADD_LEA, nargs=2)
        self.assertEqual(r["status"], "equivalent")

    def test_candidate_code_different_behavior_refuted(self):
        r = behavioral_equiv(ADD_FN, candidate_code=XOR_FN, nargs=2)
        self.assertEqual(r["status"], "refuted")

    def test_original_faults_is_inconclusive(self):
        r = behavioral_equiv(bytes.fromhex("ffffffff"), expr="x0", nargs=1)
        self.assertEqual(r["status"], "inconclusive")


@unittest.skipUnless(HAS_UNICORN, "unicorn not installed")
class TestBehaviorClaim(unittest.TestCase):
    def _binary_with_fn(self, fn, at=0x400):
        # minimal PE32+ whose .text (file 0x400) contains fn, so offset earns weight
        buf = bytearray(0x1000)
        buf[0:2] = b"MZ"; struct.pack_into("<I", buf, 0x3C, 0x80)
        po = 0x80; buf[po:po + 4] = b"PE\x00\x00"
        struct.pack_into("<HHIIIHH", buf, po + 4, 0x8664, 1, 0, 0, 0, 240, 0x0022)
        oo = po + 24
        struct.pack_into("<HBBIIIIIQII", buf, oo, 0x20B, 14, 0, 0x1000, 0, 0, 0x1000, 0x1000, 0x140000000, 0x1000, 0x200)
        s1 = oo + 240
        buf[s1:s1 + 8] = b".text\x00\x00\x00"
        struct.pack_into("<IIIIIIHHI", buf, s1 + 8, 0x500, 0x1000, 0x600, at, 0, 0, 0, 0, 0x60000020)
        buf[at:at + len(fn)] = fn
        return bytes(buf)

    def test_claim_expr_verified_from_offset_has_weight(self):
        data = self._binary_with_fn(ADD_FN)
        rep = verify_claims(data, [{
            "kind": "behavior_equiv", "offset": 0x400, "length": len(ADD_FN), "expr": "x0 + x1",
        }])
        r = rep["results"][0]
        self.assertEqual(r["verdict"], VERIFIED)
        self.assertGreater(r["weight"], 0.0)
        self.assertIn("tested", r["detail"])

    def test_claim_refuted_with_counterexample(self):
        r = Verifier(self._binary_with_fn(ADD_FN)).verify(
            Claim("behavior_equiv", {"offset": 0x400, "length": len(ADD_FN), "expr": "x0 * x1"})
        )
        self.assertEqual(r["verdict"], REFUTED)
        self.assertIn("counterexample", r["evidence"])

    def test_inline_original_is_self_referential_zero_weight(self):
        rep = verify_claims(b"\x00" * 64, [{
            "kind": "behavior_equiv", "code": ADD_FN.hex(), "expr": "x0 + x1",
        }])
        r = rep["results"][0]
        self.assertEqual(r["verdict"], VERIFIED)
        self.assertTrue(r["evidence"]["self_referential"])
        self.assertEqual(r["weight"], 0.0)


@unittest.skipUnless(HAS_UNICORN, "unicorn not installed")
class TestRunFunction32Bit(unittest.TestCase):
    """32-bit x86 arg passing must actually work (regression: 32-bit arch fell
    back to 64-bit register names, which no-op in 32-bit unicorn mode, so the
    function saw arg=0 and every 32-bit call returned 0)."""

    def test_32bit_add_works(self):
        for a, b in [(5, 3), (1, 2), (0x7FFFFFFF, 1), (0, 0)]:
            self.assertEqual(run_function(ADD_FN_32, (a, b), arch="x86"), (a + b) & 0xFFFFFFFF)

    def test_32bit_bits_derived_when_omitted(self):
        # no explicit bits: arch="x86" must imply 32-bit, result masked to 32 bits
        self.assertEqual(run_function(ADD_FN_32, (0xFFFFFFFE, 2), arch="x86"), 0)

    def test_64bit_regression_unaffected(self):
        self.assertEqual(run_function(ADD_FN, (5, 3)), 8)

    def test_arch_bits_mismatch_raises(self):
        with self.assertRaises(ValueError):
            run_function(ADD_FN, (5, 3), arch="x86_64", bits=32)
        with self.assertRaises(ValueError):
            run_function(ADD_FN_32, (5, 3), arch="x86", bits=64)

    def test_32bit_behavioral_equiv(self):
        r = behavioral_equiv(ADD_FN_32, expr="x0 + x1", nargs=2, arch="x86")
        self.assertEqual(r["status"], "equivalent")
        self.assertGreaterEqual(r["tested"], 8)

    def test_32bit_behavioral_equiv_mismatch_raises(self):
        with self.assertRaises(ValueError):
            behavioral_equiv(ADD_FN_32, expr="x0 + x1", nargs=2, arch="x86", bits=64)


if __name__ == "__main__":
    unittest.main()
