import unittest
import sys
from pathlib import Path

tools_root = Path(__file__).resolve().parent.parent
if str(tools_root) not in sys.path:
    sys.path.insert(0, str(tools_root))

from disasm import Disassembler, pattern_scan, create_patch


class TestDisassembler(unittest.TestCase):
    def test_disasm_basic_x86_64(self):
        # 90 (NOP), 50 (PUSH RAX), 58 (POP RAX), 31 C0 (XOR EAX, EAX), C3 (RET)
        code = bytes([0x90, 0x50, 0x58, 0x31, 0xC0, 0xC3])
        dis = Disassembler(arch="x86_64")
        ins = dis.disassemble(code, base_address=0x1000)

        self.assertEqual(len(ins), 5)
        self.assertEqual(ins[0].mnemonic, "nop")
        self.assertEqual(ins[1].mnemonic, "push")
        self.assertEqual(ins[2].mnemonic, "pop")
        self.assertEqual(ins[3].mnemonic, "xor")
        self.assertEqual(ins[4].mnemonic, "ret")

    def test_pattern_scan(self):
        data = b"\x48\x89\x5C\x24\x08\x55\x48\x83\xEC\x20\x90\x90\x48\x89\x5C\x24\x10\x55"
        pattern = "48 89 5c 24 ?? 55"
        matches = pattern_scan(data, pattern)
        self.assertEqual(matches, [0, 12])

    def test_create_patch(self):
        orig = b"\x90\x90\x74\x05\x90\x90"
        patched = b"\x90\x90\xEB\x05\x90\x90"
        patches = create_patch(orig, patched, base_address=0x401000)

        self.assertEqual(len(patches), 1)
        self.assertEqual(patches[0]["address"], "0x401002")
        self.assertEqual(patches[0]["length"], 1)
        self.assertEqual(patches[0]["original_bytes"], "74")
        self.assertEqual(patches[0]["patched_bytes"], "eb")


if __name__ == "__main__":
    unittest.main()
