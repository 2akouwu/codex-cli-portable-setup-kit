import json
import sys
import unittest
from pathlib import Path

tools_root = Path(__file__).resolve().parent.parent
if str(tools_root) not in sys.path:
    sys.path.insert(0, str(tools_root))

from agent import (
    ReconstructionAgent,
    demo_proposer,
    binary_facts,
    parse_claims,
    build_prompt,
    format_feedback,
)


class SeqProposer:
    """Returns a scripted response per round (holds the last one after exhaustion)."""

    def __init__(self, responses):
        self.responses = responses
        self.calls = 0

    def __call__(self, prompt):
        r = self.responses[min(self.calls, len(self.responses) - 1)]
        self.calls += 1
        return r


class TestReconstructionLoop(unittest.TestCase):
    def test_converges_after_revision(self):
        data = bytes(range(64))
        proposer = SeqProposer([
            json.dumps([{"kind": "bytes_at", "params": {"offset": 40, "expected": "ffff"}}]),            # refuted
            json.dumps([{"kind": "bytes_at", "params": {"offset": 44, "expected": data[44:52].hex()}}]),  # new, informative
        ])
        result = ReconstructionAgent(data, proposer, max_rounds=4).run("identify the header")
        self.assertTrue(result["grounded"])
        self.assertEqual(result["rounds_used"], 2)
        self.assertEqual(proposer.calls, 2)
        self.assertEqual(len(result["verified_claims"]), 1)

    def test_never_grounded_hits_cap(self):
        data = bytes.fromhex("deadbeef")
        proposer = SeqProposer([
            json.dumps([{"kind": "bytes_at", "params": {"offset": 0, "expected": "0000"}}])
        ])
        result = ReconstructionAgent(data, proposer, max_rounds=3, min_information=0.0).run("x")
        self.assertFalse(result["grounded"])
        self.assertEqual(result["rounds_used"], 3)

    def test_garbage_output_not_grounded(self):
        data = bytes.fromhex("deadbeef")
        proposer = SeqProposer(["I could not find anything useful."])
        result = ReconstructionAgent(data, proposer, max_rounds=2, min_information=0.0).run("x")
        self.assertFalse(result["grounded"])
        # empty claim set => zero total => not trustworthy
        self.assertEqual(result["final_report"]["total_claims"], 0)

    def test_demo_proposer_grounds_in_one_round(self):
        data = bytes(range(64))  # long enough for an informative tail claim
        result = ReconstructionAgent(data, demo_proposer(data), max_rounds=4).run("demo")
        self.assertTrue(result["grounded"])
        self.assertEqual(result["rounds_used"], 1)
        self.assertGreaterEqual(result["information"], 1.0)

    def test_demo_on_tiny_input_is_trivial_not_grounded(self):
        data = bytes.fromhex("4d5a9000")
        result = ReconstructionAgent(data, demo_proposer(data), max_rounds=1).run("demo")
        self.assertFalse(result["grounded"])
        rep = result["final_report"]
        self.assertTrue(rep["trustworthy"])          # nothing refuted...
        self.assertFalse(rep["informative"])          # ...but it only restated the header
        self.assertEqual(rep["trivial_verified"], 1)

    def test_feedback_lists_only_failures(self):
        data = bytes.fromhex("deadbeef")
        proposer = SeqProposer([
            json.dumps([
                {"kind": "bytes_at", "params": {"offset": 0, "expected": "dead"}},   # verified
                {"kind": "bytes_at", "params": {"offset": 0, "expected": "ffff"}},   # refuted
            ])
        ])
        result = ReconstructionAgent(data, proposer, max_rounds=1, min_information=0.0).run("x")
        fb = format_feedback(result["history"][0]["report"])
        self.assertIn("REFUTED", fb)
        self.assertNotIn("VERIFIED", fb)


class RecordingProposer:
    """Captures every prompt it is shown; returns scripted responses."""

    def __init__(self, responses):
        self.responses = responses
        self.prompts = []
        self.calls = 0

    def __call__(self, prompt):
        self.prompts.append(prompt)
        r = self.responses[min(self.calls, len(self.responses) - 1)]
        self.calls += 1
        return r


class TestEstablishedLedger(unittest.TestCase):
    """The context-hallucination defense: only grounded facts are carried forward."""

    def test_verified_and_observed_become_established(self):
        data = bytes(range(64))
        proposer = SeqProposer([json.dumps([
            {"kind": "bytes_at", "params": {"offset": 40, "expected": data[40:48].hex()}},   # verified, weighty
            {"kind": "u32_at", "params": {"offset": 50}, "observe": True},                   # observed
        ])])
        result = ReconstructionAgent(data, proposer, max_rounds=1).run("x")
        est = result["established"]
        self.assertTrue(any("bytes_at" in e for e in est), est)
        self.assertTrue(any(e.startswith("observed") for e in est), est)

    def test_refuted_hallucination_establishes_nothing(self):
        data = bytes(range(64))
        proposer = SeqProposer([json.dumps([
            {"kind": "bytes_at", "params": {"offset": 40, "expected": "ffffffffffffffff"},
             "note": "the license check is here"},
        ])])
        result = ReconstructionAgent(data, proposer, max_rounds=1).run("x")
        self.assertEqual(result["established"], [])

    def test_unverified_note_not_carried_into_next_prompt(self):
        data = bytes(range(64))
        rp = RecordingProposer([
            json.dumps([{"kind": "bytes_at", "params": {"offset": 40, "expected": "ffffffffffffffff"},
                         "note": "the license check is at 0x28"}]),   # refuted; editorial note
            json.dumps([{"kind": "bytes_at", "params": {"offset": 50, "expected": data[50:58].hex()}}]),
        ])
        ReconstructionAgent(data, rp, max_rounds=2).run("find the license check")
        round2 = rp.prompts[1]
        self.assertNotIn("license check is at 0x28", round2)   # the model's unverified prose is gone
        self.assertIn("Build ONLY on BINARY FACTS and ESTABLISHED", round2)

    def test_verified_fact_is_shown_as_established_next_round(self):
        data = bytes(range(64))
        rp = RecordingProposer([
            json.dumps([{"kind": "bytes_at", "params": {"offset": 40, "expected": data[40:48].hex()}}]),  # verified
            json.dumps([{"kind": "bytes_at", "params": {"offset": 50, "expected": data[50:58].hex()}}]),
        ])
        # min_information=2.0 so one verified claim isn't enough to ground -> a round 2 happens
        ReconstructionAgent(data, rp, max_rounds=2, min_information=2.0).run("x")
        self.assertGreaterEqual(len(rp.prompts), 2)
        self.assertIn("ESTABLISHED", rp.prompts[1])


class TestHelpers(unittest.TestCase):
    def test_parse_claims_plain_array(self):
        claims = parse_claims('[{"kind":"bytes_at","params":{"offset":0,"expected":"de"}}]')
        self.assertEqual(len(claims), 1)
        self.assertEqual(claims[0]["kind"], "bytes_at")

    def test_parse_claims_with_code_fence(self):
        raw = "Here you go:\n```json\n[{\"kind\":\"string_present\",\"params\":{\"value\":\"x\"}}]\n```"
        claims = parse_claims(raw)
        self.assertEqual(len(claims), 1)
        self.assertEqual(claims[0]["kind"], "string_present")

    def test_parse_claims_single_object(self):
        claims = parse_claims('{"kind":"pe_import","params":{"function":"CreateFileW"}}')
        self.assertEqual(len(claims), 1)

    def test_parse_claims_rejects_garbage(self):
        self.assertEqual(parse_claims("not json at all"), [])

    def test_binary_facts_detects_pe_magic(self):
        facts = binary_facts(b"MZ\x90\x00" + b"\x00" * 60)
        self.assertEqual(facts["magic_hex"][:4], "4d5a")
        self.assertIn("size", facts)

    def test_build_prompt_includes_goal_and_feedback(self):
        p = build_prompt("find the entry", {"size": 4}, feedback="prev feedback here")
        self.assertIn("find the entry", p)
        self.assertIn("prev feedback here", p)

    def test_build_prompt_shows_established(self):
        p = build_prompt("goal", {"size": 4}, established=["bytes_at @ 0x28: bytes match"])
        self.assertIn("ESTABLISHED", p)
        self.assertIn("bytes_at @ 0x28", p)


if __name__ == "__main__":
    unittest.main()
