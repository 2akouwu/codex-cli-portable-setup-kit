"""Soundness across architectures without the mature engines.

The pure-Python decoder and micro-emulator are x86/x64 only. Running ARM bytes
through them would produce junk that a wrong claim could match — a false
VERIFIED, the one thing the verifier must never do. Without capstone / unicorn
the answer for a non-x86 arch must be INCONCLUSIVE with an install hint.
"""

import sys
import unittest
from pathlib import Path
from unittest import mock

tools_root = Path(__file__).resolve().parent.parent
if str(tools_root) not in sys.path:
    sys.path.insert(0, str(tools_root))

import disasm  # noqa: E402
import emulator  # noqa: E402
from disasm import Disassembler, UnsupportedArch  # noqa: E402
from emulator import make_emulator, EmulatorError  # noqa: E402
from verifier import Verifier, Claim, VERIFIED, INCONCLUSIVE  # noqa: E402

ARM64_SUB_SP = bytes.fromhex("ff0300d1")   # sub sp, sp, #0x10


def _no_capstone(self):
    self._capstone_cs = None


class TestDisassemblerGuard(unittest.TestCase):
    def test_pure_fallback_refuses_non_x86(self):
        with mock.patch.object(Disassembler, "_init_capstone", _no_capstone):
            for arch in ("arm64", "aarch64", "arm", "mips"):
                with self.assertRaises(UnsupportedArch):
                    Disassembler(arch=arch).disassemble(ARM64_SUB_SP)
            # x86 still decodes in pure mode
            self.assertTrue(Disassembler(arch="x86_64").disassemble(bytes.fromhex("90c3")))

    def test_verifier_says_inconclusive_not_verified(self):
        data = b"\x00" * 16 + ARM64_SUB_SP + b"\x00" * 16
        with mock.patch.object(Disassembler, "_init_capstone", _no_capstone):
            v = Verifier(data)
            # the junk x86 decode of these bytes is "db 0xff; add eax, eax" — a wrong 'add' claim must not verify
            r = v.verify(Claim("instructions", {"offset": 16, "arch": "arm64", "mnemonics": ["add"]}))
            self.assertEqual(r["verdict"], INCONCLUSIVE)
            self.assertIn("capstone", r["detail"])
            r2 = v.verify(Claim("instructions", {"offset": 16, "arch": "arm64", "mnemonics": ["sub"]}))
            self.assertEqual(r2["verdict"], INCONCLUSIVE)   # unknown, not refuted either
            r3 = v.verify(Claim("instructions", {"offset": 0, "arch": "x86_64", "mnemonics": ["add"]}))
            self.assertIn(r3["verdict"], (VERIFIED, "REFUTED"))  # x86 path unaffected


class TestEmulatorGuard(unittest.TestCase):
    def test_micro_emulator_refuses_non_x86(self):
        with mock.patch.object(emulator, "HAS_UNICORN", False):
            with self.assertRaises(EmulatorError):
                make_emulator(arch="arm64")
            self.assertIsNotNone(make_emulator(arch="x86_64"))

    def test_verifier_emulate_result_inconclusive_without_unicorn(self):
        data = b"\x00" * 16 + ARM64_SUB_SP + bytes.fromhex("c0035fd6") + b"\x00" * 16
        with mock.patch.object(emulator, "HAS_UNICORN", False):
            v = Verifier(data)
            r = v.verify(Claim("emulate_result", {"offset": 16, "arch": "arm64", "expect_registers": {"sp": 0}}))
            self.assertEqual(r["verdict"], INCONCLUSIVE)
            self.assertIn("unicorn", r["detail"])


if __name__ == "__main__":
    unittest.main()
