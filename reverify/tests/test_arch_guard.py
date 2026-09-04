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
        data = bytes.fromhex("31c0c3") + b"\x00" * 13 + ARM64_SUB_SP + b"\x00" * 16   # xor eax, eax; ret; ...
        with mock.patch.object(Disassembler, "_init_capstone", _no_capstone):
            v = Verifier(data)
            # the junk x86 decode of these bytes is "db 0xff; add eax, eax" — a wrong 'add' claim must not verify
            r = v.verify(Claim("instructions", {"offset": 16, "arch": "arm64", "mnemonics": ["add"]}))
            self.assertEqual(r["verdict"], INCONCLUSIVE)
            self.assertIn("capstone", r["detail"])
            r2 = v.verify(Claim("instructions", {"offset": 16, "arch": "arm64", "mnemonics": ["sub"]}))
            self.assertEqual(r2["verdict"], INCONCLUSIVE)   # unknown, not refuted either
            r3 = v.verify(Claim("instructions", {"offset": 0, "arch": "x86_64", "mnemonics": ["xor", "ret"]}))
            self.assertEqual(r3["verdict"], VERIFIED)              # x86 path unaffected
            r4 = v.verify(Claim("instructions", {"offset": 0, "arch": "x86_64", "mnemonics": ["add"]}))
            self.assertEqual(r4["verdict"], "REFUTED")


class TestPureDecoderHonesty(unittest.TestCase):
    """The pure decoder decodes what it knows, says ``db`` for the rest, and the
    verifier treats ``db`` as unknown — never as grounds for a refutation."""

    def test_prologue_and_rex_forms_decode(self):
        with mock.patch.object(Disassembler, "_init_capstone", _no_capstone):
            d = Disassembler(arch="x86_64")
            text = [f"{i.mnemonic} {i.op_str}".strip() for i in d.disassemble(bytes.fromhex("554889e5"))]
            self.assertEqual(text, ["push rbp", "mov rbp, rsp"])
            self.assertEqual([f"{i.mnemonic} {i.op_str}" for i in d.disassemble(bytes.fromhex("4831c0"))], ["xor rax, rax"])
            self.assertEqual([f"{i.mnemonic} {i.op_str}" for i in d.disassemble(bytes.fromhex("4d89c8"))], ["mov r8, r9"])
            self.assertEqual([f"{i.mnemonic} {i.op_str}" for i in d.disassemble(bytes.fromhex("31c0"))], ["xor eax, eax"])
            self.assertEqual([i.mnemonic for i in Disassembler(arch="x86").disassemble(bytes.fromhex("55"))], ["push"])
            self.assertEqual(Disassembler(arch="x86").disassemble(bytes.fromhex("55"))[0].op_str, "ebp")

    def test_memory_forms_and_unknown_opcodes_are_db_not_guesses(self):
        with mock.patch.object(Disassembler, "_init_capstone", _no_capstone):
            d = Disassembler(arch="x86_64")
            for hexcode in ("8b45f8", "0f1f440000", "488d0500000000"):
                code = bytes.fromhex(hexcode)
                insns = d.disassemble(code)
                self.assertEqual(sum(i.size for i in insns), len(code), hexcode)   # every byte accounted for
                self.assertNotIn("mov", [i.mnemonic for i in insns[:1]] if hexcode == "8b45f8" else [], hexcode)
                self.assertTrue(any(i.mnemonic in ("db", "rex") for i in insns), hexcode)

    def test_verifier_does_not_refute_on_undecodable_bytes(self):
        data = bytes.fromhex("0f1f440000") + b"\xc3"   # nop dword ptr [rax+rax]; ret
        with mock.patch.object(Disassembler, "_init_capstone", _no_capstone):
            v = Verifier(data)
            right = v.verify(Claim("instructions", {"offset": 0, "mnemonics": ["nop"]}))
            wrong = v.verify(Claim("instructions", {"offset": 0, "mnemonics": ["call"]}))
            self.assertEqual(right["verdict"], INCONCLUSIVE)     # not verified from junk ...
            self.assertEqual(wrong["verdict"], INCONCLUSIVE)     # ... and not refuted from junk either
            self.assertIn("capstone", wrong["detail"])
            # bytes the pure decoder does understand are still judged normally
            ok = v.verify(Claim("instructions", {"offset": 5, "mnemonics": ["ret"]}))
            self.assertEqual(ok["verdict"], VERIFIED)


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
