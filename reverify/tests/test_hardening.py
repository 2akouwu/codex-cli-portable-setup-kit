"""Tests for the v0.4.0 loop hardening: address spaces, typed reads, OBSERVED,
dependencies, information scoring, echo/attrition detection, shift signals."""

import json
import struct
import sys
import unittest
from pathlib import Path

tools_root = Path(__file__).resolve().parent.parent
if str(tools_root) not in sys.path:
    sys.path.insert(0, str(tools_root))

from verifier import (
    Verifier, Claim, verify_claims, summarize, claim_key,
    VERIFIED, REFUTED, INCONCLUSIVE, OBSERVED, INVALIDATED,
)
from agent import ReconstructionAgent, binary_facts, format_feedback
from binary import parse_binary, shannon_entropy


def synthetic_pe_with_code() -> bytes:
    """PE32+ whose .text (RVA 0x1000, file 0x400) starts with push rbp; mov rbp,rsp; ... deadbeef."""
    buf = bytearray(0x1000)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    po = 0x80
    buf[po:po + 4] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", buf, po + 4, 0x8664, 2, 0, 0, 0, 240, 0x0022)
    oo = po + 24
    struct.pack_into("<HBBIIIIIQII", buf, oo, 0x20B, 14, 0, 0x1000, 0x2000, 0, 0x1000, 0x1000, 0x140000000, 0x1000, 0x200)
    s1 = oo + 240
    buf[s1:s1 + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIIIIIHHI", buf, s1 + 8, 0x500, 0x1000, 0x600, 0x400, 0, 0, 0, 0, 0x60000020)
    s2 = s1 + 40
    buf[s2:s2 + 8] = b".data\x00\x00\x00"
    struct.pack_into("<IIIIIIHHI", buf, s2 + 8, 0x200, 0x2000, 0x200, 0xA00, 0, 0, 0, 0, 0xC0000040)
    code = bytes.fromhex("554889e5" "deadbeef" "78563412")  # push rbp; mov rbp,rsp; deadbeef; u32le 0x12345678
    buf[0x400:0x400 + len(code)] = code
    return bytes(buf)


def synthetic_pe32() -> bytes:
    """Minimal 32-bit PE (i386, ImageBase 0x400000) laid out per the PE32 spec."""
    buf = bytearray(0x1000)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    po = 0x80
    buf[po:po + 4] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", buf, po + 4, 0x014C, 1, 0, 0, 0, 224, 0x0102)
    oo = po + 24
    # magic, maj, min, SizeOfCode, SizeInit, SizeUninit, Entry, BaseOfCode, BaseOfData, ImageBase, SectAlign, FileAlign
    struct.pack_into("<HBBIIIIIIIII", buf, oo, 0x10B, 14, 0, 0x1000, 0x2000, 0, 0x1000, 0x1000, 0x2000, 0x400000, 0x1000, 0x200)
    s1 = oo + 224
    buf[s1:s1 + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIIIIIHHI", buf, s1 + 8, 0x500, 0x1000, 0x600, 0x400, 0, 0, 0, 0, 0x60000020)
    return bytes(buf)


class TestPEParserLayouts(unittest.TestCase):
    """Pins the optional-header layouts: both backends must agree on real values."""

    def test_pe32plus_image_base_both_backends(self):
        pe = synthetic_pe_with_code()
        for pref in ("pure", "auto"):
            info = parse_binary(pe, prefer=pref)
            self.assertIsNone(info.error, pref)
            self.assertEqual(info.image_base, 0x140000000, pref)
            self.assertEqual(info.entrypoint, 0x1000, pref)
            self.assertEqual(info.bits, 64, pref)

    def test_pe32_parses_on_both_backends(self):
        pe = synthetic_pe32()
        for pref in ("pure", "auto"):
            info = parse_binary(pe, prefer=pref)
            self.assertIsNone(info.error, pref)
            self.assertEqual(info.format, "PE", pref)
            self.assertEqual(info.arch, "x86", pref)
            self.assertEqual(info.bits, 32, pref)
            self.assertEqual(info.image_base, 0x400000, pref)
            self.assertEqual(info.entrypoint, 0x1000, pref)
            self.assertEqual([s.name for s in info.sections], [".text"], pref)

    def test_malformed_pe_degrades_instead_of_crashing(self):
        junk = b"MZ" + b"\x00" * 62 + b"\xff" * 200
        info = parse_binary(junk, prefer="pure")
        self.assertEqual(info.format, "PE")
        self.assertIsNotNone(info.error)


class TestAddressSpaces(unittest.TestCase):
    def setUp(self):
        self.pe = synthetic_pe_with_code()
        self.v = Verifier(self.pe)

    def test_rva_translates_to_file_offset(self):
        r = self.v.verify(Claim("bytes_at", {"offset": 0x1000, "space": "rva", "expected": "554889e5"}))
        self.assertEqual(r["verdict"], VERIFIED)
        self.assertEqual(r["evidence"]["address"]["file_offset"], "0x400")
        self.assertEqual(r["evidence"]["address"]["rva"], "0x1000")

    def test_va_translates_to_file_offset(self):
        r = self.v.verify(Claim("bytes_at", {"offset": 0x140001000, "space": "va", "expected": "554889e5"}))
        self.assertEqual(r["verdict"], VERIFIED)
        self.assertEqual(r["evidence"]["address"]["va"], "0x140001000")

    def test_file_offset_echoes_rva_and_va(self):
        r = self.v.verify(Claim("bytes_at", {"offset": 0x400, "expected": "554889e5"}))
        self.assertEqual(r["verdict"], VERIFIED)
        self.assertEqual(r["evidence"]["address"]["rva"], "0x1000")
        self.assertEqual(r["evidence"]["address"]["va"], "0x140001000")

    def test_rva_outside_sections_is_inconclusive(self):
        r = self.v.verify(Claim("bytes_at", {"offset": 0x9999999, "space": "rva", "expected": "00"}))
        self.assertEqual(r["verdict"], INCONCLUSIVE)

    def test_binaryinfo_translation_helpers(self):
        info = parse_binary(self.pe)
        self.assertEqual(info.rva_to_offset(0x1000), 0x400)
        self.assertEqual(info.offset_to_rva(0x400), 0x1000)
        self.assertEqual(info.va_to_offset(0x140001004), 0x404)


class TestTypedReadsAndObserve(unittest.TestCase):
    def setUp(self):
        self.pe = synthetic_pe_with_code()
        self.v = Verifier(self.pe)

    def test_u32_at_verified_little_endian(self):
        r = self.v.verify(Claim("u32_at", {"offset": 0x408, "expected": 0x12345678}))
        self.assertEqual(r["verdict"], VERIFIED)

    def test_u32_at_refuted_with_nearest_hint(self):
        r = self.v.verify(Claim("u32_at", {"offset": 0x404, "expected": 0x12345678}))
        self.assertEqual(r["verdict"], REFUTED)
        self.assertEqual(r["evidence"]["nearest_offset_of_expected"], "0x408")

    def test_bytes_at_refuted_nearest_hint(self):
        r = self.v.verify(Claim("bytes_at", {"offset": 0x400, "expected": "deadbeef"}))
        self.assertEqual(r["verdict"], REFUTED)
        self.assertEqual(r["evidence"]["nearest_offset_of_expected"], "0x404")

    def test_observe_bytes(self):
        r = self.v.verify(Claim("bytes_at", {"offset": 0x404, "length": 4}, observe=True))
        self.assertEqual(r["verdict"], OBSERVED)
        self.assertEqual(r["evidence"]["actual"], "deadbeef")

    def test_missing_expected_means_observe(self):
        r = self.v.verify(Claim("u32_at", {"offset": 0x408}))
        self.assertEqual(r["verdict"], OBSERVED)
        self.assertEqual(r["evidence"]["actual"], hex(0x12345678))

    def test_observed_is_not_scored(self):
        rep = verify_claims(self.pe, [{"kind": "u32_at", "offset": 0x408}])
        self.assertEqual(rep["observed"], 1)
        self.assertEqual(rep["verified"], 0)
        self.assertFalse(rep["trustworthy"])  # nothing asserted


class TestSelfReferentialAndOperands(unittest.TestCase):
    def test_inline_code_not_in_binary_is_self_referential_zero_weight(self):
        rep = verify_claims(b"\x00" * 64, [{
            "kind": "emulate_result", "code": "b805000000c3", "arch": "x86", "expect_registers": {"eax": 5},
        }])
        r = rep["results"][0]
        self.assertEqual(r["verdict"], VERIFIED)
        self.assertTrue(r["evidence"]["self_referential"])
        self.assertEqual(r["weight"], 0.0)
        self.assertEqual(rep["information"], 0.0)

    def test_inline_code_present_in_binary_carries_weight(self):
        code = bytes.fromhex("b805000000c3")
        rep = verify_claims(b"\x90" * 16 + code + b"\x90" * 16, [{
            "kind": "emulate_result", "code": code.hex(), "arch": "x86", "expect_registers": {"eax": 5},
        }])
        r = rep["results"][0]
        self.assertFalse(r["evidence"]["self_referential"])
        self.assertGreater(r["weight"], 0)

    def test_emulate_from_offset_keeps_weight(self):
        code = bytes.fromhex("b807000000c3")
        rep = verify_claims(b"\x00\x00" + code, [{
            "kind": "emulate_result", "offset": 2, "length": 6, "arch": "x86", "expect_registers": {"eax": 7},
        }])
        self.assertGreaterEqual(rep["results"][0]["weight"], 0.7)


class TestMeasuredSurprisal(unittest.TestCase):
    """Weights come from the binary, not from a table by claim kind."""

    def test_zero_padding_claim_is_worthless(self):
        data = b"\x00" * 4096 + bytes(range(200, 208))
        rep = verify_claims(data, [
            {"kind": "bytes_at", "offset": 1000, "expected": "00" * 8},            # verifies, says nothing
            {"kind": "bytes_at", "offset": 4096, "expected": data[4096:].hex()},   # unique tail
        ])
        self.assertEqual(rep["results"][0]["verdict"], VERIFIED)
        self.assertLess(rep["results"][0]["weight"], 0.05)
        self.assertGreaterEqual(rep["results"][1]["weight"], 0.9)
        self.assertIn("occurrences", rep["results"][0]["evidence"]["weight_basis"])
        self.assertFalse(rep["grounded"] and rep["information"] < 0.9)

    def test_ubiquitous_sequence_weighs_little(self):
        unit = bytes.fromhex("5590")  # push ; nop — decodable by both disassemblers
        data = unit * 50 + bytes.fromhex("deadbeef")
        rep = verify_claims(data, [{"kind": "instructions", "offset": 0, "mnemonics": ["push", "nop"]}])
        self.assertEqual(rep["results"][0]["verdict"], VERIFIED)
        self.assertLess(rep["results"][0]["weight"], 0.2)

    def test_pattern_weight_scales_with_match_count(self):
        data = b"\x90" * 100 + b"\xde\xad"
        rep = verify_claims(data, [
            {"kind": "pattern_present", "pattern": "90"},
            {"kind": "pattern_present", "pattern": "de ad"},
        ])
        self.assertLess(rep["results"][0]["weight"], rep["results"][1]["weight"])

    def test_emulating_padding_is_worthless(self):
        rep = verify_claims(b"\x00" * 256, [{
            "kind": "emulate_result", "offset": 0, "length": 64, "arch": "x86_64", "expect_registers": {"rax": 0},
        }])
        self.assertEqual(rep["results"][0]["weight"], 0.0)

    def test_u32_weight_reflects_rarity(self):
        common = (0x00000000).to_bytes(4, "little")
        rare = (0x12345678).to_bytes(4, "little")
        data = common * 64 + rare
        rep = verify_claims(data, [
            {"kind": "u32_at", "offset": 0, "expected": 0},
            {"kind": "u32_at", "offset": 256, "expected": 0x12345678},
        ])
        self.assertLess(rep["results"][0]["weight"], 0.05)
        self.assertGreater(rep["results"][1]["weight"], 0.6)

    def test_instructions_operands_mismatch_refuted(self):
        data = bytes.fromhex("554889e5")  # push rbp ; mov rbp, rsp
        ok = Verifier(data).verify(Claim("instructions", {"offset": 0, "mnemonics": ["push", "mov"], "operands": ["rbp", "rbp, rsp"]}))
        bad = Verifier(data).verify(Claim("instructions", {"offset": 0, "mnemonics": ["push", "mov"], "operands": ["rbp", "rsp, rbp"]}))
        self.assertEqual(ok["verdict"], VERIFIED)
        self.assertEqual(bad["verdict"], REFUTED)


class TestDependenciesAndScoring(unittest.TestCase):
    def test_refuted_root_invalidates_dependents(self):
        data = bytes.fromhex("deadbeefcafe")
        rep = verify_claims(data, [
            {"kind": "bytes_at", "id": "root", "offset": 0, "expected": "0000"},                 # refuted
            {"kind": "bytes_at", "id": "leaf", "offset": 4, "expected": "cafe", "depends_on": ["root"]},  # would verify
        ])
        leaf = rep["results"][1]
        self.assertEqual(leaf["verdict"], INVALIDATED)
        self.assertEqual(leaf["verdict_before_invalidation"], VERIFIED)
        self.assertEqual(rep["invalidated"], 1)
        self.assertFalse(rep["trustworthy"])

    def test_claims_restating_facts_weigh_zero(self):
        data = bytes(range(64))
        facts = binary_facts(data)
        rep = verify_claims(data, [
            {"kind": "bytes_at", "offset": 0, "expected": data[:4].hex()},     # inside shown header -> trivial
            {"kind": "bytes_at", "offset": 40, "expected": data[40:48].hex()},  # beyond header -> informative
        ], facts=facts)
        self.assertTrue(rep["results"][0]["trivial"])
        self.assertEqual(rep["results"][0]["weight"], 0.0)
        self.assertFalse(rep["results"][1]["trivial"])
        self.assertEqual(rep["results"][1]["weight"], 1.0)
        self.assertEqual(rep["trivial_verified"], 1)
        self.assertTrue(rep["grounded"])

    def test_only_trivial_claims_is_trustworthy_but_not_informative(self):
        data = bytes(range(64))
        rep = verify_claims(data, [{"kind": "bytes_at", "offset": 0, "expected": data[:4].hex()}], facts=binary_facts(data))
        self.assertTrue(rep["trustworthy"])
        self.assertFalse(rep["informative"])
        self.assertFalse(rep["grounded"])

    def test_duplicates_count_once(self):
        data = bytes(range(64))
        rep = verify_claims(data, [
            {"kind": "bytes_at", "offset": 40, "expected": data[40:48].hex()},
            {"kind": "bytes_at", "offset": 40, "expected": data[40:48].hex()},
        ])
        self.assertTrue(rep["results"][1]["duplicate"])
        self.assertEqual(rep["results"][1]["weight"], 0.0)
        self.assertEqual(rep["duplicates"], 1)
        self.assertEqual(rep["information"], 1.0)

    def test_weight_tiers_discriminate(self):
        data = bytes(range(64))
        rep = verify_claims(data, [
            {"kind": "bytes_at", "offset": 40, "expected": data[40:41].hex()},    # 1 byte -> 0.4
            {"kind": "bytes_at", "offset": 40, "expected": data[40:48].hex()},    # 8 bytes -> 1.0
        ])
        self.assertLess(rep["results"][0]["weight"], rep["results"][1]["weight"])

    def test_claim_key_ignores_observe_flag(self):
        self.assertEqual(claim_key("bytes_at", {"offset": 1, "observe": True}), claim_key("bytes_at", {"offset": 1}))


class SeqProposer:
    def __init__(self, responses):
        self.responses = responses
        self.calls = 0

    def __call__(self, prompt):
        r = self.responses[min(self.calls, len(self.responses) - 1)]
        self.calls += 1
        return r


class TestLoopHardening(unittest.TestCase):
    def test_echo_of_previous_observed_value_scores_zero(self):
        data = bytes(range(64))
        # round 1 asserts wrong bytes at 40 -> REFUTED with actual=28292a2b...; round 2 parrots that actual.
        proposer = SeqProposer([
            json.dumps([{"kind": "bytes_at", "params": {"offset": 40, "expected": "ffffffffffffffff"}}]),
            json.dumps([{"kind": "bytes_at", "params": {"offset": 40, "expected": data[40:48].hex()}}]),
        ])
        result = ReconstructionAgent(data, proposer, max_rounds=2).run("x")
        r2 = result["history"][1]
        self.assertEqual(r2["echoed"], 1)
        self.assertEqual(r2["report"]["results"][0]["weight"], 0.0)
        self.assertFalse(result["grounded"])

    def test_attrition_counts_dropped_claims(self):
        data = bytes(range(64))
        proposer = SeqProposer([
            json.dumps([
                {"kind": "bytes_at", "params": {"offset": 40, "expected": "00"}},
                {"kind": "bytes_at", "params": {"offset": 50, "expected": "00"}},
            ]),
            json.dumps([{"kind": "bytes_at", "params": {"offset": 50, "expected": data[50:58].hex()}}]),
        ])
        result = ReconstructionAgent(data, proposer, max_rounds=2).run("x")
        self.assertEqual(result["history"][1]["attrition"], 1)

    def test_observed_values_fold_into_facts(self):
        data = bytes(range(64))
        proposer = SeqProposer([json.dumps([{"kind": "u32_at", "params": {"offset": 40}, "observe": True}])])
        result = ReconstructionAgent(data, proposer, max_rounds=1).run("x")
        self.assertIn("u32_at@0x28", result["observed"])

    def test_samples_are_deduped(self):
        data = bytes(range(64))
        proposer = SeqProposer([json.dumps([{"kind": "bytes_at", "params": {"offset": 40, "expected": data[40:48].hex()}}])])
        result = ReconstructionAgent(data, proposer, max_rounds=1, samples=3).run("x")
        self.assertEqual(proposer.calls, 3)
        self.assertEqual(result["final_report"]["total_claims"], 1)
        self.assertTrue(result["grounded"])

    def test_feedback_marks_trivial_without_verified_word(self):
        data = bytes(range(64))
        rep = verify_claims(data, [{"kind": "bytes_at", "offset": 0, "expected": data[:4].hex()}], facts=binary_facts(data))
        fb = format_feedback(rep)
        self.assertIn("TRIVIAL", fb)
        self.assertNotIn("VERIFIED", fb)


class TestFactsAndShift(unittest.TestCase):
    def test_facts_are_keyed_and_addressed(self):
        facts = binary_facts(synthetic_pe_with_code())
        self.assertIn("0x0", facts["first_bytes"])
        self.assertEqual(facts["sections"][0]["name"], ".text")
        self.assertEqual(facts["sections"][0]["file_offset"], "0x400")
        self.assertEqual(facts["sections"][0]["rva"], "0x1000")
        self.assertIn("shift_signals", facts)
        self.assertIn("section_entropy", facts["shift_signals"])

    def test_entropy_helper(self):
        self.assertEqual(shannon_entropy(b"\x00" * 100), 0.0)
        self.assertGreater(shannon_entropy(bytes(range(256))), 7.9)


if __name__ == "__main__":
    unittest.main()
