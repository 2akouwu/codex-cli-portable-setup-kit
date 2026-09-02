import unittest
import sys
from pathlib import Path

tools_root = Path(__file__).resolve().parent.parent
if str(tools_root) not in sys.path:
    sys.path.insert(0, str(tools_root))

from emulator import MicroEmulator


class TestMicroEmulator(unittest.TestCase):
    def test_emulation_execution(self):
        # B8 2A 00 00 00 (MOV EAX, 42)
        # 50             (PUSH RAX)
        # 5B             (POP RBX) -> RBX = 42
        # C3             (RET)
        code = bytes([0xB8, 0x2A, 0x00, 0x00, 0x00, 0x50, 0x5B, 0xC3])
        emu = MicroEmulator(arch="x86_64")
        emu.load_code(code, base_address=0x1000)
        state = emu.run(max_steps=50)

        self.assertTrue(state["halted"])
        self.assertEqual(emu.reg_read("rax"), 42)
        self.assertEqual(emu.reg_read("rbx"), 42)
        self.assertGreaterEqual(state["steps_executed"], 4)

    def test_xor_arithmetic(self):
        # B8 05 00 00 00 (MOV EAX, 5)
        # 31 C0          (XOR EAX, EAX) -> EAX = 0
        # C3             (RET)
        code = bytes([0xB8, 0x05, 0x00, 0x00, 0x00, 0x31, 0xC0, 0xC3])
        emu = MicroEmulator(arch="x86_64")
        emu.load_code(code, base_address=0x2000)
        state = emu.run(max_steps=50)

        self.assertEqual(emu.reg_read("rax"), 0)
        self.assertTrue(state["halted"])


if __name__ == "__main__":
    unittest.main()
