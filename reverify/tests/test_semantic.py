"""Semantic layer: function boundaries, call graph, xrefs from a real engine.

Two things are pinned here. Without an engine the verifier says INCONCLUSIVE
rather than guessing (only the entry point and exports are known function
starts). With angr, the export table — parsed by lief or the pure parser,
independently of angr — is an oracle: every export must be a function start
the engine recovered, which is the "who verifies the verifier" check for the
semantic backend.
"""

import json
import os
import sys
import unittest
from pathlib import Path

tools_root = Path(__file__).resolve().parent.parent
if str(tools_root) not in sys.path:
    sys.path.insert(0, str(tools_root))

from backends import HAS_ANGR  # noqa: E402
from binary import parse_binary  # noqa: E402
from semantic import semantic_view, SEMANTIC_KINDS  # noqa: E402
from verifier import Verifier, Claim, VERIFIED, REFUTED, INCONCLUSIVE, OBSERVED  # noqa: E402
from ledger import Ledger, DERIVED  # noqa: E402
import mcp_server  # noqa: E402

DLL = r"C:\Windows\System32\msimg32.dll"
HAVE_DLL = os.path.exists(DLL)


def mk(kind, params, observe=False):
    return Claim.from_dict({"kind": kind, "params": params, "observe": observe})


class TestKinds(unittest.TestCase):
    def test_semantic_kinds_are_supported(self):
        for k in SEMANTIC_KINDS:
            self.assertIn(k, Verifier.SUPPORTED)

    def test_raw_bytes_are_inconclusive(self):
        v = Verifier(bytes(range(64)))
        r = v.verify(mk("function_at", {"offset": 0}))
        self.assertEqual(r["verdict"], INCONCLUSIVE)


@unittest.skipUnless(HAVE_DLL, "needs a small Windows system DLL")
class TestPureFallback(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(DLL, "rb") as f:
            cls.data = f.read()
        cls.info = parse_binary(cls.data)
        cls.view = semantic_view(cls.data, prefer="pure")

    def test_exports_and_entry_are_known_function_starts(self):
        self.assertFalse(self.view.complete)
        self.assertTrue(self.info.export_rvas)
        for name, rva in self.info.export_rvas.items():
            f = self.view.function_at(rva)
            self.assertIsNotNone(f, name)
            self.assertEqual(f.name, name)
        self.assertIsNotNone(self.view.function_at(self.view.entry_rva))
        self.assertIn("reverify[angr]", self.view.summary()["install_hint"])

    def test_verifier_never_guesses_without_an_engine(self):
        v = Verifier(self.data)
        v._sem_cache = self.view
        name, rva = next(iter(self.info.export_rvas.items()))
        r = v.verify(mk("function_at", {"offset": rva, "space": "rva"}))
        self.assertEqual(r["verdict"], VERIFIED)
        self.assertIn("pure fallback", r["evidence"]["strength"])
        self.assertEqual(v.verify(mk("function_at", {"name": name}))["verdict"], VERIFIED)
        r2 = v.verify(mk("function_at", {"offset": rva + 64, "space": "rva"}))
        self.assertEqual(r2["verdict"], INCONCLUSIVE)            # unknown, not refuted
        r3 = v.verify(mk("calls", {"from": name, "to": "SetLastError"}))
        self.assertEqual(r3["verdict"], INCONCLUSIVE)
        self.assertIn("reverify[angr]", r3["detail"])
        r4 = v.verify(mk("references", {"to": rva, "space": "rva"}))
        self.assertEqual(r4["verdict"], INCONCLUSIVE)
        r5 = v.verify(mk("reachable_from_entry", {"name": name}))
        self.assertEqual(r5["verdict"], INCONCLUSIVE)


@unittest.skipUnless(HAVE_DLL and HAS_ANGR, "needs angr (pip install reverify[angr])")
class TestAngrSemantic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(DLL, "rb") as f:
            cls.data = f.read()
        cls.info = parse_binary(cls.data)
        cls.view = semantic_view(cls.data)
        cls.v = Verifier(cls.data)

    def test_engine_is_complete(self):
        self.assertEqual(self.view.engine, "angr")
        self.assertTrue(self.view.complete)
        self.assertGreater(len(self.view.functions), 5)
        self.assertTrue(self.view.edges)
        self.assertIsNotNone(self.view.function_at(self.view.entry_rva))

    def test_exports_are_function_starts_differential(self):
        # the export table (lief / pure parser) is independent of angr
        missing = [n for n, rva in self.info.export_rvas.items() if self.view.function_at(rva) is None]
        self.assertEqual(missing, [])

    def test_function_at(self):
        name, rva = sorted(self.info.export_rvas.items(), key=lambda kv: kv[1])[0]
        r = self.v.verify(mk("function_at", {"offset": rva, "space": "rva"}))
        self.assertEqual(r["verdict"], VERIFIED, r["detail"])
        self.assertEqual(r["evidence"]["function"]["name"], name)
        self.assertEqual(r["evidence"]["engine"], "angr")
        self.assertGreater(r["evidence"]["function"]["size"], 0)
        r2 = self.v.verify(mk("function_at", {"offset": rva + 3, "space": "rva"}))
        self.assertEqual(r2["verdict"], REFUTED)
        self.assertTrue("inside_function" in r2["evidence"] or "nearest_function" in r2["evidence"])
        self.assertEqual(self.v.verify(mk("function_at", {"name": name}))["verdict"], VERIFIED)
        self.assertEqual(self.v.verify(mk("function_at", {"name": "NoSuchFunction_xyz"}))["verdict"], REFUTED)
        self.assertEqual(self.v.verify(mk("function_at", {"offset": rva, "space": "rva"}, observe=True))["verdict"], OBSERVED)
        r6 = self.v.verify(mk("function_at", {"offset": rva, "space": "rva", "name": "WrongName"}))
        self.assertEqual(r6["verdict"], REFUTED)
        rep = self.v.verify_all([mk("function_at", {"offset": rva, "space": "rva"})])
        self.assertGreater(rep["results"][0]["weight"], 0)

    def test_calls(self):
        src = next(f for f in sorted(self.view.functions.values(), key=lambda f: f.rva) if f.is_export and f.callees)
        dst = self.view.functions[src.callees[0]]
        r = self.v.verify(mk("calls", {"from": src.name, "to": dst.name}))
        self.assertEqual(r["verdict"], VERIFIED, r["detail"])
        self.assertEqual(r["evidence"]["from_function"]["name"], src.name)
        # by address, from inside the function body rather than its start
        r_addr = self.v.verify(mk("calls", {"from": src.rva + 1, "space": "rva", "to": dst.name}))
        self.assertEqual(r_addr["verdict"], VERIFIED, r_addr["detail"])
        non = next(f for f in self.view.functions.values()
                   if f.rva not in src.callees and f.rva != src.rva and not f.is_import)
        r2 = self.v.verify(mk("calls", {"from": src.name, "to": non.name}))
        self.assertEqual(r2["verdict"], REFUTED)
        self.assertTrue(r2["evidence"]["callees"])                # the feedback that lets a model fix the claim
        r3 = self.v.verify(mk("calls", {"from": src.name, "to": "NoSuchImport_xyz"}))
        self.assertEqual(r3["verdict"], REFUTED)
        obs = self.v.verify(mk("calls", {"from": src.name}, observe=True))
        self.assertEqual(obs["verdict"], OBSERVED)
        self.assertEqual(obs["evidence"]["callee_count"], len(src.callees))

    def test_references(self):
        pick = None
        for dst, refs in self.view.xrefs.items():
            if self.info.rva_to_offset(dst) is None:
                continue
            fr = next((x for x in refs if x.get("function_rva") is not None), None)
            if fr is not None:
                pick = (dst, refs, fr)
                break
        self.assertIsNotNone(pick, "expected at least one data reference inside a section")
        dst, refs, fr = pick
        r = self.v.verify(mk("references", {"to": dst, "space": "rva", "from": fr["function_rva"]}))
        self.assertEqual(r["verdict"], VERIFIED, r["detail"])
        referencing = {x.get("function_rva") for x in refs}
        other = next(f for f in self.view.functions.values() if not f.is_import and f.rva not in referencing)
        r2 = self.v.verify(mk("references", {"to": dst, "space": "rva", "from": other.rva}))
        self.assertEqual(r2["verdict"], REFUTED)
        self.assertTrue(r2["evidence"]["referenced_by"])
        self.assertEqual(self.v.verify(mk("references", {"to": dst, "space": "rva"}))["verdict"], VERIFIED)
        obs = self.v.verify(mk("references", {"to": dst, "space": "rva"}, observe=True))
        self.assertEqual(obs["verdict"], OBSERVED)

    def test_reachable_from_entry(self):
        r = self.v.verify(mk("reachable_from_entry", {"offset": self.view.entry_rva, "space": "rva"}))
        self.assertEqual(r["verdict"], VERIFIED, r["detail"])
        unreachable = [f for f in self.view.functions.values() if not f.is_import and f.rva not in self.view.reachable]
        if unreachable:
            r2 = self.v.verify(mk("reachable_from_entry", {"offset": unreachable[0].rva, "space": "rva"}))
            self.assertEqual(r2["verdict"], REFUTED)

    def test_ledger_records_the_derived_tier(self):
        name, rva = next(iter(self.info.export_rvas.items()))
        rep = self.v.verify_all([mk("function_at", {"offset": rva, "space": "rva"})])
        led = Ledger.for_bytes(self.data, persist=False)
        led.record(rep)
        self.assertEqual(led.facts[0]["tier"], DERIVED)
        self.assertIn(name, led.facts[0]["line"])
        self.assertEqual(led.counts()["derived"], 1)
        self.assertIn("1 derived", led.context_text())

    def test_mcp_re_semantic(self):
        out = json.loads(mcp_server.handle_tool_call("re_semantic", {"file_path": DLL, "query": "functions", "limit": 5}))
        self.assertEqual(out["summary"]["engine"], "angr")
        self.assertEqual(len(out["functions"]), 5)
        name = next(iter(self.info.export_rvas))
        out2 = json.loads(mcp_server.handle_tool_call("re_semantic", {"file_path": DLL, "query": "callees", "name": name}))
        self.assertIn("callees", out2)
        self.assertEqual(out2["function"]["name"], name)
        out3 = json.loads(mcp_server.handle_tool_call("re_semantic", {"file_path": DLL, "query": "function_at", "name": "nope_xyz"}))
        self.assertIn("error", out3)


if __name__ == "__main__":
    unittest.main()
