import os
import sys
import unittest
from pathlib import Path

toolkit_dir = Path(__file__).resolve().parent.parent
if str(toolkit_dir) not in sys.path:
    sys.path.insert(0, str(toolkit_dir))

from cli import extract_strings, auto_triage
from disasm import pattern_scan, create_patch


class TestCliExtended(unittest.TestCase):
    def test_pattern_scan_with_wildcards(self):
        data = bytes.fromhex("48895C2408554883EC20488B05123456784885C0")
        # Exact match
        matches = pattern_scan(data, "48 89 5C 24 08")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0], 0)

        # Wildcard match
        matches_wildcard = pattern_scan(data, "48 8B ?? ?? ?? ?? ?? 48 85 C0")
        self.assertEqual(len(matches_wildcard), 1)
        self.assertEqual(matches_wildcard[0], 10)

    def test_extract_strings(self):
        data = b"SomeHeader\x00\x00TargetFunction_Init\x00\x00" + "UnicodeString_123".encode("utf-16le")
        strings = extract_strings(data, min_len=4)
        ascii_strings = [s["string"] for s in strings if s["type"] == "ASCII"]
        unicode_strings = [s["string"] for s in strings if s["type"] == "UTF-16LE"]
        
        self.assertIn("SomeHeader", ascii_strings)
        self.assertIn("TargetFunction_Init", ascii_strings)
        self.assertIn("UnicodeString_123", unicode_strings)

    def test_create_patch_diff(self):
        orig = bytes.fromhex("90909090")
        patched = bytes.fromhex("90CC90C3")
        diffs = create_patch(orig, patched, base_address=0x1000)
        self.assertEqual(len(diffs), 2)
        self.assertEqual(diffs[0]["offset"], "0x1")
        self.assertEqual(diffs[0]["patched_bytes"], "cc")
        self.assertEqual(diffs[1]["offset"], "0x3")
        self.assertEqual(diffs[1]["patched_bytes"], "c3")

    def test_auto_triage_raw(self):
        data = b"MZ\x90\x00" + b"\x00" * 100 + b"MyTestString\x00"
        report = auto_triage(data, filename="test.dll")
        self.assertEqual(report["type"], "Windows PE Binary (EXE/DLL/SYS)")
        self.assertIn("MyTestString", report["top_strings"])


if __name__ == "__main__":
    unittest.main()
