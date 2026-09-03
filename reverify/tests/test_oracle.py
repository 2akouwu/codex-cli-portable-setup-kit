"""Cross-engine oracles and known-answer tests for the instruction layer.

The differential parser tests catch parser bugs by disagreeing with lief. The
disassembler and emulator had no such independent check — only hand-written unit
tests that share the author's blind spots. This module adds, mirroring how
mature tools verify these components:

- **Known-answer tests (KAT)**: byte sequences with hand-verified decodings
  (Intel SDM encodings). The ground truth is external to *both* our decoder and
  capstone, so a shared blind spot is caught. (cf. NIST/Wycheproof vectors.)
- **Disassembler differential**: our pure-Python decoder vs capstone on the
  opcode subset the pure decoder implements. (cf. the disassembler SoK.)
- **Emulator differential**: our pure MicroEmulator vs Unicorn — run the same
  code in two independent engines, compare registers. (cf. Linaro RISU: real
  CPU vs QEMU.)
- **Engine fuzz**: random bytes into the disassembler and emulator must never
  raise, never loop; the pure decoder must consume every byte.
"""

import random
import sys
import unittest
from pathlib import Path

tools_root = Path(__file__).resolve().parent.parent
if str(tools_root) not in sys.path:
    sys.path.insert(0, str(tools_root))

from backends import HAS_CAPSTONE, HAS_UNICORN
from disasm import Disassembler
from emulator import MicroEmulator, UnicornEmulator


def _pure(arch):
    d = Disassembler(arch=arch)
    d._capstone_cs = None  # force the pure-Python path regardless of capstone
    return d


def _capstone(arch):
    d = Disassembler(arch=arch)
    if d._capstone_cs is None:
        raise unittest.SkipTest("capstone not active")
    return d


# (hex, arch, expected_mnemonic, operand_substring_or_None) — hand-verified encodings.
KAT = [
    ("90", "x86", "nop", None),
    ("c3", "x86", "ret", None),
    ("cc", "x86", "int3", None),
    ("50", "x86", "push", "eax"),
    ("55", "x86", "push", "ebp"),
    ("58", "x86", "pop", "eax"),
    ("b805000000", "x86", "mov", "eax"),      # mov eax, 5
    ("b9ff000000", "x86", "mov", "ecx"),      # mov ecx, 0xff
    ("31c8", "x86", "xor", "eax"),            # xor eax, ecx
    ("01c8", "x86", "add", "eax"),            # add eax, ecx
    ("29c8", "x86", "sub", "eax"),            # sub eax, ecx
    ("ebfe", "x86", "jmp", None),             # jmp $
]

# capstone-only ground truth (opcodes the pure decoder does not implement).
KAT_CAPSTONE = [
    ("4889e5", "x86_64", "mov", "rbp"),        # mov rbp, rsp
    ("4883ec28", "x86_64", "sub", "rsp"),      # sub rsp, 0x28
    ("4831c0", "x86_64", "xor", "rax"),        # xor rax, rax
    ("488d0500000000", "x86_64", "lea", "rax"),  # lea rax, [rip+0]
    ("ff2500000000", "x86_64", "jmp", None),   # jmp qword [rip+0]
]


class TestDisasmKAT(unittest.TestCase):
    def test_pure_decoder_matches_known_answers(self):
        for hexs, arch, mnem, op in KAT:
            insns = _pure(arch).disassemble(bytes.fromhex(hexs))
            self.assertTrue(insns, f"{hexs}: no output")
            self.assertEqual(insns[0].mnemonic, mnem, f"{hexs}: pure mnemonic")
            if op is not None:
                self.assertIn(op, insns[0].op_str, f"{hexs}: pure operand")

    @unittest.skipUnless(HAS_CAPSTONE, "capstone not installed")
    def test_capstone_matches_known_answers(self):
        for hexs, arch, mnem, op in KAT + KAT_CAPSTONE:
            insns = _capstone(arch).disassemble(bytes.fromhex(hexs))
            self.assertTrue(insns, f"{hexs}: no output")
            self.assertEqual(insns[0].mnemonic, mnem, f"{hexs}: capstone mnemonic")
            if op is not None:
                self.assertIn(op, insns[0].op_str, f"{hexs}: capstone operand")


@unittest.skipUnless(HAS_CAPSTONE, "capstone not installed")
class TestDisasmDifferential(unittest.TestCase):
    """Where the pure decoder is confident, it must agree with capstone."""

    # opcodes the pure decoder implements, in 32-bit (avoids REX / jcc naming).
    SAMPLES = [
        "90", "c3", "cc", "50", "51", "57", "58", "5f",
        "b8efbeadde", "b912345678",
        "31c0", "31c8", "01c1", "29d0", "33c3", "03c1", "2bc2",
        "ebfe",
    ]

    def test_pure_agrees_with_capstone(self):
        pure, cs = _pure("x86"), _capstone("x86")
        for hexs in self.SAMPLES:
            data = bytes.fromhex(hexs)
            p = pure.disassemble(data)[0]
            c = cs.disassemble(data)[0]
            self.assertEqual(p.mnemonic, c.mnemonic, f"{hexs}: {p.mnemonic} vs {c.mnemonic}")
            self.assertEqual(p.size, c.size, f"{hexs}: size {p.size} vs {c.size}")


@unittest.skipUnless(HAS_UNICORN, "unicorn not installed")
class TestEmulatorDifferential(unittest.TestCase):
    """Run identical code in the pure emulator and Unicorn; registers must agree.

    Uses only opcodes MicroEmulator implements (mov r,imm32; add/xor r,r; push;
    pop), in 32-bit mode.
    """

    PROGRAMS = [
        # mov eax,7 ; mov ecx,3 ; add eax,ecx ; ret
        ("b807000000b90300000001c8c3", ["eax", "ecx"]),
        # mov eax,0xff ; mov edx,0x0f ; xor eax,edx ; ret
        ("b8ff000000ba0f00000031d0c3", ["eax", "edx"]),
        # mov eax,5 ; push eax ; pop ecx ; ret
        ("b80500000050" "59" "c3", ["eax", "ecx"]),
        # mov ebx,0x11223344 ; mov esi,1 ; add ebx,esi ; ret
        ("bb44332211be0100000001f3c3", ["ebx", "esi"]),
    ]

    def test_pure_matches_unicorn(self):
        for hexs, regs in self.PROGRAMS:
            code = bytes.fromhex(hexs)
            pe = MicroEmulator(arch="x86"); pe.load_code(code); pe.run(50)
            ue = UnicornEmulator(arch="x86"); ue.load_code(code); ue.run(50)
            for r in regs:
                self.assertEqual(
                    pe.reg_read(r), ue.reg_read(r),
                    f"{hexs}: {r} pure={hex(pe.reg_read(r))} unicorn={hex(ue.reg_read(r))}",
                )


class TestEngineRobustness(unittest.TestCase):
    def test_pure_disasm_consumes_all_bytes_and_never_raises(self):
        rng = random.Random(7)
        for _ in range(400):
            n = rng.randint(0, 40)
            data = bytes(rng.getrandbits(8) for _ in range(n))
            try:
                insns = _pure("x86_64").disassemble(data)
            except Exception as exc:  # noqa: BLE001
                self.fail(f"pure disasm raised on {data.hex()}: {exc}")
            self.assertEqual(sum(i.size for i in insns), n, f"pure decoder skipped bytes on {data.hex()}")

    @unittest.skipUnless(HAS_CAPSTONE, "capstone not installed")
    def test_capstone_never_raises(self):
        rng = random.Random(8)
        for _ in range(400):
            data = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 40)))
            try:
                _capstone("x86_64").disassemble(data)
            except Exception as exc:  # noqa: BLE001
                self.fail(f"capstone raised on {data.hex()}: {exc}")

    def test_emulator_never_raises_and_halts(self):
        rng = random.Random(9)
        for arch in ("x86", "x86_64"):
            for _ in range(150):
                code = bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 32)))
                emu = MicroEmulator(arch=arch)
                try:
                    emu.load_code(code)
                    emu.run(200)
                except Exception as exc:  # noqa: BLE001
                    self.fail(f"MicroEmulator raised on {code.hex()} ({arch}): {exc}")
                self.assertLessEqual(emu.steps_executed, 200)

    @unittest.skipUnless(HAS_UNICORN, "unicorn not installed")
    def test_unicorn_emulator_never_raises(self):
        rng = random.Random(10)
        for arch in ("x86", "x86_64"):
            for _ in range(100):
                code = bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 32)))
                emu = UnicornEmulator(arch=arch)
                try:
                    emu.load_code(code)
                    emu.run(100)
                except Exception as exc:  # noqa: BLE001
                    self.fail(f"UnicornEmulator raised on {code.hex()} ({arch}): {exc}")


if __name__ == "__main__":
    unittest.main()
