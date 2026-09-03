import struct
import unittest
import sys
from pathlib import Path

tools_root = Path(__file__).resolve().parent.parent
if str(tools_root) not in sys.path:
    sys.path.insert(0, str(tools_root))

from pe_parser import PEParser, BinaryParseError


def create_synthetic_pe32_plus() -> bytes:
    """Create a minimal synthetic PE32+ (x64) binary buffer."""
    buf = bytearray(1024)
    # DOS Header
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)  # e_lfanew = 128

    pe_offset = 0x80
    buf[pe_offset : pe_offset + 4] = b"PE\x00\x00"

    # File Header (Machine=AMD64 (0x8664), NumSections=2, SizeOfOptionalHeader=240, Char=0x0002)
    struct.pack_into("<HHIIIHH", buf, pe_offset + 4, 0x8664, 2, 0x12345678, 0, 0, 240, 0x0022)

    # Optional Header (Magic=0x20B (PE32+), EntryPoint=0x1000, ImageBase=0x140000000)
    opt_offset = pe_offset + 24
    struct.pack_into("<HBBIIIIIQII", buf, opt_offset, 0x20B, 14, 0, 0x1000, 0x2000, 0, 0x1000, 0x1000, 0x140000000, 0x1000, 0x200)

    # Section Headers
    sec1_offset = opt_offset + 240
    # .text
    buf[sec1_offset : sec1_offset + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIIIIIHHI", buf, sec1_offset + 8, 0x500, 0x1000, 0x600, 0x400, 0, 0, 0, 0, 0x60000020)

    # .data
    sec2_offset = sec1_offset + 40
    buf[sec2_offset : sec2_offset + 8] = b".data\x00\x00\x00"
    struct.pack_into("<IIIIIIHHI", buf, sec2_offset + 8, 0x200, 0x2000, 0x200, 0xA00, 0, 0, 0, 0, 0xC0000040)

    return bytes(buf)


class TestPEParser(unittest.TestCase):
    def test_invalid_magic(self):
        with self.assertRaises(BinaryParseError):
            PEParser(b"INVALID_HEADER_DATA_NOT_MZ")

    def test_synthetic_pe(self):
        data = create_synthetic_pe32_plus()
        parser = PEParser(data)
        self.assertTrue(parser.is_64bit)
        self.assertIn("x64", parser.file_header["MachineName"])
        self.assertEqual(len(parser.sections), 2)
        self.assertEqual(parser.sections[0]["Name"], ".text")
        self.assertEqual(parser.sections[1]["Name"], ".data")
        self.assertEqual(parser.optional_header["AddressOfEntryPoint"], "0x1000")

        summary = parser.summary()
        self.assertEqual(summary["format"], "PE")
        self.assertTrue(summary["is_64bit"])
        self.assertEqual(summary["sections"], [".text", ".data"])


if __name__ == "__main__":
    unittest.main()
