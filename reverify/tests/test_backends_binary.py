import struct
import sys
import unittest
from pathlib import Path

tools_root = Path(__file__).resolve().parent.parent
if str(tools_root) not in sys.path:
    sys.path.insert(0, str(tools_root))

from backends import backend_report, HAS_LIEF, HAS_UNICORN, HAS_CAPSTONE
from binary import parse_binary, BinaryInfo, Section
from emulator import make_emulator, MicroEmulator, UnicornEmulator
from verifier import Verifier, Claim, VERIFIED, REFUTED, INCONCLUSIVE


def synthetic_pe() -> bytes:
    buf = bytearray(1024)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    po = 0x80
    buf[po:po + 4] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", buf, po + 4, 0x8664, 2, 0, 0, 0, 240, 0x0022)
    oo = po + 24
    struct.pack_into("<HBBIIIIIQII", buf, oo, 0x20B, 14, 0, 0x1000, 0x2000, 0, 0x1000, 0x1000, 0x140000000, 0x1000, 0x200)
    s1 = oo + 240
    buf[s1:s1 + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIIIIIHHI", buf, s1 + 8, 0x500, 0x1000, 0x600, 0x400, 0, 0, 0, 0, 0x60000020)
    s2 = s1 + 40
    buf[s2:s2 + 8] = b".data\x00\x00\x00"
    struct.pack_into("<IIIIIIHHI", buf, s2 + 8, 0x200, 0x2000, 0x200, 0xA00, 0, 0, 0, 0, 0xC0000040)
    return bytes(buf)


def minimal_elf64() -> bytes:
    eh = bytearray(64)
    eh[0:4] = b"\x7fELF"
    eh[4] = 2  # 64-bit
    eh[5] = 1  # little
    eh[6] = 1
    struct.pack_into("<HHIQQQIHHHHHH", eh, 16, 2, 62, 1, 0x401000, 0, 0, 0, 64, 56, 0, 64, 0, 0)
    return bytes(eh)


class TestBackendReport(unittest.TestCase):
    def test_report_shape(self):
        r = backend_report()
        for k in ("disassembly", "emulation", "binary_parsing"):
            self.assertIn("engine", r[k])
        self.assertIsInstance(r["full_fidelity"], bool)


class TestParseBinary(unittest.TestCase):
    def test_synthetic_pe(self):
        info = parse_binary(synthetic_pe())
        self.assertEqual(info.format, "PE")
        self.assertEqual(info.arch, "x86_64")
        self.assertEqual(info.bits, 64)
        self.assertIsNotNone(info.section(".text"))
        self.assertEqual(info.section(".text").virtual_address, 0x1000)

    def test_synthetic_pe_pure_backend(self):
        info = parse_binary(synthetic_pe(), prefer="pure")
        self.assertEqual(info.backend, "pure-python")
        self.assertEqual([s.name for s in info.sections], [".text", ".data"])

    def test_minimal_elf(self):
        info = parse_binary(minimal_elf64())
        self.assertEqual(info.format, "ELF")
        self.assertEqual(info.arch, "x86_64")
        self.assertEqual(info.entrypoint, 0x401000)

    def test_minimal_elf_pure(self):
        info = parse_binary(minimal_elf64(), prefer="pure")
        self.assertEqual(info.format, "ELF")
        self.assertEqual(info.backend, "pure-python")
        self.assertEqual(info.entrypoint, 0x401000)

    def test_raw(self):
        self.assertEqual(parse_binary(b"\x00\x01\x02\x03").format, "raw")

    @unittest.skipUnless(HAS_LIEF, "lief not installed")
    def test_lief_reads_real_executable(self):
        info = parse_binary(Path(sys.executable).read_bytes())
        self.assertEqual(info.backend, "lief")
        self.assertIn(info.format, ("PE", "ELF", "MachO"))
        self.assertTrue(info.sections)
        self.assertTrue(info.imports)


class TestNewClaims(unittest.TestCase):
    def setUp(self):
        self.pe = synthetic_pe()

    def test_section_present_verified(self):
        r = Verifier(self.pe).verify(Claim("section_present", {"name": ".text"}))
        self.assertEqual(r["verdict"], VERIFIED)

    def test_section_present_wrong_va_refuted(self):
        r = Verifier(self.pe).verify(Claim("section_present", {"name": ".text", "virtual_address": 0x9999}))
        self.assertEqual(r["verdict"], REFUTED)

    def test_section_absent_refuted(self):
        r = Verifier(self.pe).verify(Claim("section_present", {"name": ".nope"}))
        self.assertEqual(r["verdict"], REFUTED)

    def test_import_absent_on_synthetic_refuted(self):
        r = Verifier(self.pe).verify(Claim("import_present", {"function": "CreateFileW"}))
        self.assertEqual(r["verdict"], REFUTED)

    def test_export_absent_refuted(self):
        r = Verifier(self.pe).verify(Claim("export_present", {"name": "Whatever"}))
        self.assertEqual(r["verdict"], REFUTED)

    def test_import_on_raw_is_inconclusive(self):
        r = Verifier(b"not a binary at all").verify(Claim("import_present", {"function": "x"}))
        self.assertEqual(r["verdict"], INCONCLUSIVE)

    def test_pe_import_alias(self):
        r = Verifier(self.pe).verify(Claim("pe_import", {"dll": "kernel32.dll", "function": "CreateFileW"}))
        self.assertEqual(r["verdict"], REFUTED)  # synthetic PE has no imports

    @unittest.skipUnless(HAS_LIEF, "lief not installed")
    def test_import_present_on_real_exe(self):
        info = parse_binary(Path(sys.executable).read_bytes())
        # pick a real imported function to assert on
        func = next(f for funcs in info.imports.values() for f in funcs)
        r = Verifier(Path(sys.executable).read_bytes()).verify(Claim("import_present", {"function": func}))
        self.assertEqual(r["verdict"], VERIFIED)


class TestEmulatorBackends(unittest.TestCase):
    def test_pure_backend_selectable(self):
        self.assertIsInstance(make_emulator("x86", prefer="pure"), MicroEmulator)

    def test_emulate_result_pure_backend(self):
        # mov eax,5 ; mov ecx,3 ; add eax,ecx ; ret  -> eax=8 through the micro-emulator
        r = Verifier(b"").verify(Claim("emulate_result", {
            "code": "b805000000b90300000001c8c3", "arch": "x86",
            "backend": "pure", "expect_registers": {"eax": 8},
        }))
        self.assertEqual(r["verdict"], VERIFIED)
        self.assertEqual(r["evidence"]["backend"], "pure-python")

    @unittest.skipUnless(HAS_UNICORN, "unicorn not installed")
    def test_unicorn_auto_selected(self):
        self.assertIsInstance(make_emulator("x86_64"), UnicornEmulator)

    @unittest.skipUnless(HAS_UNICORN, "unicorn not installed")
    def test_unicorn_imul(self):
        emu = UnicornEmulator("x86_64")
        emu.load_code(bytes.fromhex("48c7c00700000048c7c103000000480fafc1"))  # rax=7; rcx=3; imul rax,rcx
        emu.run(50)
        self.assertEqual(emu.reg_read("rax"), 21)

    @unittest.skipUnless(HAS_UNICORN, "unicorn not installed")
    def test_unicorn_arm64(self):
        emu = UnicornEmulator("arm64")
        emu.load_code(bytes.fromhex("e00080d2210080d20000018b"))  # x0=7; x1=1; add x0,x0,x1
        emu.run(50)
        self.assertEqual(emu.reg_read("x0"), 8)

    @unittest.skipUnless(HAS_UNICORN, "unicorn not installed")
    def test_emulate_result_via_unicorn_imul(self):
        r = Verifier(b"").verify(Claim("emulate_result", {
            "code": "48c7c00700000048c7c103000000480fafc1", "arch": "x86_64",
            "expect_registers": {"rax": 21},
        }))
        self.assertEqual(r["verdict"], VERIFIED)
        self.assertEqual(r["evidence"]["backend"], "unicorn")


if __name__ == "__main__":
    unittest.main()
