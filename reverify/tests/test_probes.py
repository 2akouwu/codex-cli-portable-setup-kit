"""Regression tests for the prior-probe benchmark (benchmarks/hallucination_probes.py).

The probes are exercised against synthetic binaries so the scorecard's
guard logic (the false-VERIFIED check) is pinned down without needing a
corpus of real system binaries.
"""

import struct
import sys
import unittest
from pathlib import Path

# This test lives in reverify/tests/. The benchmark (benchmarks/) imports the
# package as ``reverify.*`` from the repo root, so mirror that here and make
# the whole run use the source tree (not any installed copy of reverify).
pkg_dir = Path(__file__).resolve().parent.parent       # .../reverify
repo_root = pkg_dir.parent                              # .../reverify-main
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))
sys.path.insert(0, str(repo_root / "benchmarks"))

import hallucination_probes as hp
from reverify.binary import parse_binary
from reverify.verifier import Verifier, VERIFIED, REFUTED
from reverify.backends import HAS_CAPSTONE


def synthetic_pe(with_md5_constant: bool = False, prologue_bytes: bytes = b"") -> bytes:
    """Minimal synthetic PE32+ (x86_64), sections .text (VA 0x1000, file 0x400) / .data."""
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
    if with_md5_constant:
        # MD5 A0 (0x67452301) as a little-endian immediate at the entry point.
        buf[0x400:0x404] = bytes.fromhex(hp.MD5_A0_LE.replace(" ", ""))
    if prologue_bytes:
        buf[0x400:0x400 + len(prologue_bytes)] = prologue_bytes
    return bytes(buf)


def minimal_elf64() -> bytes:
    eh = bytearray(64)
    eh[0:4] = b"\x7fELF"
    eh[4] = 2  # 64-bit
    eh[5] = 1  # little
    eh[6] = 1
    struct.pack_into("<HHIQQQIHHHHHH", eh, 16, 2, 62, 1, 0x401000, 0, 0, 0, 64, 56, 0, 64, 0, 0)
    return bytes(eh)


def run_probe(probe, binary):
    """Run one probe on a binary; return (verdict, false_accept_flagged)."""
    info = parse_binary(binary)
    v = Verifier(binary)
    built = probe(info, binary)
    assert built is not None, "probe unexpectedly not applicable"
    claim, guard = built
    r = v.verify(claim)
    false_accept = r["verdict"] == VERIFIED and not guard(r["verdict"], r["evidence"])
    return r["verdict"], false_accept


class TestProbeApplicability(unittest.TestCase):
    def test_x86_only_probes_skip_arm(self):
        data = minimal_elf64()
        info = parse_binary(data)
        info.arch = "arm64"
        self.assertIsNone(hp.probe_prologue(info, data))
        self.assertIsNone(hp.probe_md5_const(info, data))


class TestSectionProbe(unittest.TestCase):
    def test_rodata_absent_in_pe_refuted(self):
        vd, fa = run_probe(hp.probe_section_rodata, synthetic_pe())
        self.assertEqual(vd, REFUTED)
        self.assertFalse(fa)

    def test_rodata_applies_to_elf(self):
        vd, fa = run_probe(hp.probe_section_rodata, minimal_elf64())
        self.assertEqual(vd, REFUTED)  # minimal ELF carries no section table
        self.assertFalse(fa)


class TestImportProbe(unittest.TestCase):
    def test_gets_absent_refuted(self):
        vd, fa = run_probe(hp.probe_import_gets, synthetic_pe())
        self.assertEqual(vd, REFUTED)
        self.assertFalse(fa)

    def test_gets_applies_to_elf(self):
        vd, fa = run_probe(hp.probe_import_gets, minimal_elf64())
        self.assertEqual(vd, REFUTED)
        self.assertFalse(fa)


class TestMd5Probe(unittest.TestCase):
    def test_md5_constant_absent_refuted(self):
        vd, fa = run_probe(hp.probe_md5_const, synthetic_pe())
        self.assertEqual(vd, REFUTED)
        self.assertFalse(fa)

    def test_md5_constant_present_verified_not_false_accept(self):
        vd, fa = run_probe(hp.probe_md5_const, synthetic_pe(with_md5_constant=True))
        self.assertEqual(vd, VERIFIED)
        self.assertFalse(fa)  # the constant really is in the bytes

    def test_md5_const_skips_arm(self):
        info = parse_binary(minimal_elf64())
        info.arch = "arm64"
        self.assertIsNone(hp.probe_md5_const(info, minimal_elf64()))


@unittest.skipUnless(HAS_CAPSTONE, "capstone not installed")
class TestPrologueProbe(unittest.TestCase):
    def test_textbook_prologue_verified_not_false_accept(self):
        # 55 push rbp ; 48 89 e5 mov rbp, rsp
        vd, fa = run_probe(hp.probe_prologue, synthetic_pe(prologue_bytes=b"\x55\x48\x89\xe5"))
        self.assertEqual(vd, VERIFIED)
        self.assertFalse(fa)

    def test_non_textbook_prologue_refuted(self):
        vd, fa = run_probe(hp.probe_prologue, synthetic_pe(prologue_bytes=b"\x31\xf6"))  # xor esi, esi
        self.assertEqual(vd, REFUTED)
        self.assertFalse(fa)


class TestGuardInversion(unittest.TestCase):
    """The guard must flag a VERIFIED verdict whose evidence contradicts the claim."""

    def test_prologue_guard_flags_contradictory_verdict(self):
        pe = synthetic_pe()  # entry bytes are zero, not the prior
        info = parse_binary(pe)
        claim, guard = hp.probe_prologue(info, pe)
        # Simulate a buggy verifier: VERIFIED but the actual bytes are not the prior.
        evidence = {"actual_mnemonics": ["xor", "mov"]}
        self.assertFalse(guard(VERIFIED, evidence))
        # A consistent verdict (actual == prior) is not a false accept.
        self.assertTrue(guard(VERIFIED, {"actual_mnemonics": ["push", "mov"]}))
        self.assertTrue(guard(REFUTED, {"actual_mnemonics": ["push", "mov"]}))


if __name__ == "__main__":
    unittest.main()
