# -*- coding: utf-8 -*-
import unittest
import sys
import json
from pathlib import Path

toolkit_dir = Path(__file__).resolve().parent.parent
if str(toolkit_dir) not in sys.path:
    sys.path.insert(0, str(toolkit_dir))

from mcp_server import handle_tool_call, TOOLS_MANIFEST


class TestMcpServer(unittest.TestCase):
    def test_tools_manifest_structure(self):
        self.assertGreaterEqual(len(TOOLS_MANIFEST), 4)
        names = [t["name"] for t in TOOLS_MANIFEST]
        self.assertIn("re_auto_triage", names)
        self.assertIn("re_disasm", names)
        self.assertIn("re_parse_pe", names)

    def test_mcp_disasm_tool_call(self):
        res_str = handle_tool_call("re_disasm", {"hex_bytes": "90C3", "arch": "x86_64"})
        res = json.loads(res_str)
        self.assertEqual(len(res), 2)
        self.assertEqual(res[0]["mnemonic"], "nop")
        self.assertEqual(res[1]["mnemonic"], "ret")


if __name__ == "__main__":
    unittest.main()
