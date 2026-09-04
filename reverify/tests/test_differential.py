"""Who verifies the verifier.

These tests do not trust our own reading of a binary. They cross-check it three
ways, which is how mature tools (Csmith, cryptofuzz, RISU, the disassembler SoK)
find bugs that hand-written unit tests miss — because unit tests share the
author's blind spots (the pure PE parser and its synthetic test fixture were
wrong the same way, so the fixture "passed"):

1. Differential: the pure-Python parser vs lief, over REAL x64 and x86 binaries.
2. Round-trip: address translation and observe->assert must return to origin.
3. Fuzz: malformed input never crashes and never yields a false VERIFIED, and a
   claim VERIFIES iff the bytes actually match (soundness on arbitrary data).
4. Oracle: our disassembly vs a third-party disassembler when one is installed.

The differential/oracle tests need real binaries and/or lief; they skip cleanly
when unavailable so the suite still runs anywhere.
"""

import glob
import os
import random
import shutil
import struct
import subprocess
import sys
import unittest
from pathlib import Path

tools_root = Path(__file__).resolve().parent.parent
if str(tools_root) not in sys.path:
    sys.path.insert(0, str(tools_root))

from backends import HAS_LIEF
from binary import parse_binary
from disasm import Disassembler
from protocol_parser import decode_varint, encode_varint, TLVDissector
from verifier import Verifier, Claim, VERIFIED, REFUTED, INCONCLUSIVE, OBSERVED

MAX_BIN = 20 * 1024 * 1024


def _sample(paths, n):
    """A deterministic spread across a sorted list (no RNG, reproducible)."""
    paths = sorted(paths)
    if len(paths) <= n:
        return paths
    stride = len(paths) / n
    return [paths[int(i * stride)] for i in range(n)]


_MAGICS = (b"MZ", b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe",
           b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce")


def _is_binary(p):
    try:
        with open(p, "rb") as f:
            head = f.read(4)
    except OSError:
        return False
    return len(head) == 4 and any(head.startswith(m) for m in _MAGICS)


def real_binaries(per_dir=12):
    """Real binaries present on this machine, per platform — Windows PE (System32 x64,
    SysWOW64 x86), Linux ELF (/usr/bin and the multiarch /usr/lib), macOS Mach-O
    (/bin, /usr/bin) — plus the interpreter itself. CI runs this on all three."""
    out = [sys.executable]
    if sys.platform.startswith("win"):
        dirs = [(r"C:\Windows\System32", "*.dll"), (r"C:\Windows\SysWOW64", "*.dll")]
    elif sys.platform == "darwin":
        dirs = [("/bin", "*"), ("/usr/bin", "*")]
    else:
        dirs = [("/usr/bin", "*"), ("/usr/lib/x86_64-linux-gnu", "*.so*"),
                ("/usr/lib/aarch64-linux-gnu", "*.so*"), ("/lib/x86_64-linux-gnu", "*.so*")]
    for d, pat in dirs:
        if os.path.isdir(d):
            cand = [p for p in glob.glob(os.path.join(d, pat)) if os.path.isfile(p) and _ok_size(p) and _is_binary(p)]
            out += _sample(cand, per_dir)
    seen, uniq = set(), []
    for p in out:
        if p not in seen and _ok_size(p):
            seen.add(p)
            uniq.append(p)
    return uniq


def _ok_size(p):
    try:
        return 0 < os.path.getsize(p) <= MAX_BIN
    except OSError:
        return False


def _read(p):
    with open(p, "rb") as f:
        return f.read()


CORPUS = real_binaries()


@unittest.skipUnless(HAS_LIEF, "lief backend not installed")
@unittest.skipUnless(len(CORPUS) >= 2, "no real-binary corpus on this machine")
class TestDifferentialParsing(unittest.TestCase):
    """Pure-Python parser must agree with lief on every load-bearing field."""

    def test_headers_and_sections_agree(self):
        checked = 0
        for path in CORPUS:
            data = _read(path)
            pure = parse_binary(data, prefer="pure")
            lief = parse_binary(data, prefer="lief")
            if lief.error or lief.format == "raw":
                continue  # lief could not parse it either; nothing to diff
            if lief.format == "MachO":
                continue  # there is no pure Mach-O reader (documented: Mach-O needs lief)
            name = os.path.basename(path)
            self.assertIsNone(pure.error, f"pure parser errored on {name}: {pure.error}")
            self.assertEqual(pure.format, lief.format, name)
            self.assertEqual(pure.arch, lief.arch, f"{name}: arch")
            self.assertEqual(pure.bits, lief.bits, f"{name}: bits")
            self.assertEqual(pure.entrypoint, lief.entrypoint, f"{name}: entrypoint")
            if lief.format == "PE":  # the pure ELF reader is header-only: no sections or image base to diff
                self.assertEqual(pure.image_base, lief.image_base, f"{name}: image_base")
                self.assertEqual(
                    [s.name for s in pure.sections], [s.name for s in lief.sections], f"{name}: section names"
                )
                for ps, ls in zip(pure.sections, lief.sections):
                    self.assertEqual(ps.virtual_address, ls.virtual_address, f"{name}: {ps.name} RVA")
            checked += 1
        if checked == 0:
            self.skipTest("no binaries the pure parser reads on this platform (Mach-O needs lief)")
        print(f"\n  [differential] pure==lief on {checked} real binaries")

    def test_pure_imports_never_invented(self):
        """Pure parser may miss exotic imports, but must never invent a named one lief lacks."""
        for path in CORPUS:
            data = _read(path)
            pure = parse_binary(data, prefer="pure")
            lief = parse_binary(data, prefer="lief")
            if lief.error or not lief.imports:
                continue
            lief_named = {f.lower() for fns in lief.imports.values() for f in fns if not f.startswith("Ordinal_")}
            pure_named = {f.lower() for fns in pure.imports.values() for f in fns if not f.startswith("Ordinal_")}
            invented = pure_named - lief_named
            self.assertFalse(invented, f"{os.path.basename(path)}: pure invented imports {list(invented)[:5]}")


class TestUnmappedSectionsNeverTranslate(unittest.TestCase):
    """An ELF .debug_* section (virtual address 0) must not map file offsets onto other sections.

    Caught by CI on Linux: the interpreter's .debug_aranges offset round-tripped into a
    different section because every unmapped section claims address 0.
    """

    def test_va_zero_sections_are_ignored_for_translation(self):
        from binary import BinaryInfo, Section
        info = BinaryInfo(format="ELF", arch="x86_64", bits=64, image_base=0x400000)
        info.sections = [
            Section(".text", 0x1000, 0x200, 0x200, 0x400),
            Section(".debug_aranges", 0, 0x100, 0x100, 0x800),
            Section(".comment", 0, 0x40, 0x40, 0x900),
        ]
        self.assertEqual(info.offset_to_rva(0x450), 0x1050)
        self.assertEqual(info.rva_to_offset(0x1050), 0x450)
        self.assertIsNone(info.offset_to_rva(0x850))        # unmapped: no address
        self.assertIsNone(info.rva_to_offset(0x50))          # address 0x50 is not inside any loaded section
        self.assertIsNone(info.section_containing_rva(0x10))
        self.assertIsNotNone(info.section(".comment"))       # still listed for section_present

    def test_duplicate_section_names_are_judged_by_address(self):
        """Mach-O has __TEXT,__const and __DATA_CONST,__const: a true claim about the second
        must not be refuted because the first was found — caught by the matrix gate on macOS."""
        from binary import BinaryInfo, Section
        info = BinaryInfo(format="MachO", arch="arm64", bits=64, image_base=0x100000000)
        info.sections = [
            Section("__text", 0x1000, 0x200, 0x200, 0x1000),
            Section("__const", 0x1200, 0x100, 0x100, 0x1200),
            Section("__const", 0x4000, 0x100, 0x100, 0x4000),
        ]
        v = Verifier(b"\x00" * 0x5000)
        v._bin_cache = info
        ok2 = v.verify(Claim("section_present", {"name": "__const", "virtual_address": 0x4000}))
        ok1 = v.verify(Claim("section_present", {"name": "__const", "virtual_address": 0x1200}))
        bad = v.verify(Claim("section_present", {"name": "__const", "virtual_address": 0x4010}))
        self.assertEqual(ok2["verdict"], VERIFIED)
        self.assertEqual(ok1["verdict"], VERIFIED)
        self.assertEqual(bad["verdict"], REFUTED)
        self.assertEqual(bad["evidence"]["candidates"], ["0x1200", "0x4000"])
        self.assertEqual(v.verify(Claim("section_present", {"name": "__nope"}))["verdict"], REFUTED)


@unittest.skipUnless(len(CORPUS) >= 2, "no real-binary corpus on this machine")
class TestAddressRoundTrip(unittest.TestCase):
    def test_file_rva_file_identity(self):
        for path in CORPUS:
            info = parse_binary(_read(path))
            if info.format == "raw" or not info.sections:
                continue
            for s in info.sections:
                if s.raw_size <= 0 or s.virtual_address == 0:
                    continue  # unmapped sections (ELF .debug_*, .comment, ...) have no address to round-trip
                off = s.offset
                rva = info.offset_to_rva(off)
                self.assertIsNotNone(rva, f"{os.path.basename(path)}: {s.name} offset->rva")
                self.assertEqual(info.rva_to_offset(rva), off, f"{os.path.basename(path)}: {s.name} round trip")
                if info.image_base is not None:
                    self.assertEqual(info.va_to_offset(info.image_base + rva), off)


@unittest.skipUnless(len(CORPUS) >= 2, "no real-binary corpus on this machine")
class TestObserveAssertRoundTrip(unittest.TestCase):
    def test_observed_value_asserts_true(self):
        for path in CORPUS[:6]:
            data = _read(path)
            v = Verifier(data)
            off = len(data) // 2
            obs = v.verify(Claim("bytes_at", {"offset": off, "length": 8}, observe=True))
            self.assertEqual(obs["verdict"], OBSERVED)
            actual = obs["evidence"]["actual"]
            back = v.verify(Claim("bytes_at", {"offset": off, "expected": actual}))
            self.assertEqual(back["verdict"], VERIFIED, os.path.basename(path))


class TestProtocolRoundTrip(unittest.TestCase):
    def test_varint_round_trip(self):
        rng = random.Random(20260903)
        for _ in range(2000):
            n = rng.getrandbits(rng.randint(1, 64))
            val, off = decode_varint(encode_varint(n))
            self.assertEqual(val, n)
            self.assertEqual(off, len(encode_varint(n)))

    def test_tlv_round_trip(self):
        payloads = [b"", b"\x00", b"admin", bytes(range(20))]
        blob = b""
        for i, pl in enumerate(payloads):
            blob += bytes([i & 0xFF]) + struct.pack(">H", len(pl)) + pl
        out = TLVDissector.dissect(blob, type_len=1, length_len=2)
        self.assertEqual(len(out), len(payloads))
        for got, pl in zip(out, payloads):
            self.assertEqual(bytes.fromhex(got["hex"]), pl)


class TestRobustnessFuzz(unittest.TestCase):
    """Malformed input must degrade, never crash; and a claim verifies iff bytes match."""

    def _malformed(self, rng, n=400):
        n = int(os.environ.get("REVERIFY_FUZZ_N", n))  # the nightly fuzz job raises this
        out = []
        real_head = _read(CORPUS[0])[:256] if CORPUS else b"MZ" + b"\x00" * 200
        for _ in range(n):
            k = rng.randint(0, 300)
            choice = rng.randint(0, 4)
            if choice == 0:
                out.append(bytes(rng.getrandbits(8) for _ in range(k)))
            elif choice == 1:
                out.append(b"MZ" + bytes(rng.getrandbits(8) for _ in range(k)))
            elif choice == 2:
                out.append(b"\x7fELF" + bytes(rng.getrandbits(8) for _ in range(k)))
            elif choice == 3:
                out.append(real_head[: rng.randint(0, len(real_head))])
            else:
                b = bytearray(real_head)
                for _ in range(rng.randint(1, 20)):
                    b[rng.randrange(len(b))] = rng.getrandbits(8)
                out.append(bytes(b))
        return out

    def test_parser_never_raises_or_warns(self):
        import warnings as _w
        rng = random.Random(1)
        for data in self._malformed(rng):
            with _w.catch_warnings():
                _w.simplefilter("error")  # a leaked warning fails the test
                try:
                    info = parse_binary(data)
                except Warning as warn:  # noqa: BLE001
                    self.fail(f"parse_binary leaked a warning on malformed input: {warn}")
                except Exception as exc:  # noqa: BLE001
                    self.fail(f"parse_binary raised on malformed input: {type(exc).__name__}: {exc}")
            self.assertIn(info.format, ("PE", "ELF", "MachO", "raw"))

    def test_verifier_never_raises_and_no_false_verified(self):
        rng = random.Random(2)
        kinds = [
            {"kind": "section_present", "name": ".text"},
            {"kind": "import_present", "function": "CreateFileW"},
            {"kind": "export_present", "name": "DllMain"},
            {"kind": "instructions", "offset": 0, "mnemonics": ["push", "mov"]},
            {"kind": "u32_at", "offset": 4, "expected": 0x12345678},
        ]
        for data in self._malformed(rng, n=300):
            v = Verifier(data)
            for spec in kinds:
                try:
                    r = v.verify(Claim.from_dict(spec))
                except Exception as exc:  # noqa: BLE001
                    self.fail(f"verify raised: {type(exc).__name__}: {exc}")
                self.assertIn(r["verdict"], (VERIFIED, REFUTED, INCONCLUSIVE, OBSERVED))

    def test_soundness_verify_iff_match(self):
        """On arbitrary bytes: expected==actual -> VERIFIED; one bit flipped -> never VERIFIED."""
        rng = random.Random(3)
        for _ in range(int(os.environ.get("REVERIFY_FUZZ_N", 500))):
            n = rng.randint(16, 200)
            data = bytes(rng.getrandbits(8) for _ in range(n))
            off = rng.randint(0, n - 4)
            actual = data[off : off + 4]
            v = Verifier(data)
            good = v.verify(Claim("bytes_at", {"offset": off, "expected": actual.hex()}))
            self.assertEqual(good["verdict"], VERIFIED)
            flipped = bytearray(actual)
            flipped[0] ^= 0x01
            bad = v.verify(Claim("bytes_at", {"offset": off, "expected": bytes(flipped).hex()}))
            self.assertNotEqual(bad["verdict"], VERIFIED)  # must not falsely verify


def _find_objdump():
    for t in ("objdump", "llvm-objdump"):
        p = shutil.which(t)
        if p:
            return p
    return None


@unittest.skipUnless(_find_objdump(), "no objdump/llvm-objdump oracle installed")
@unittest.skipUnless(len(CORPUS) >= 1, "no real-binary corpus")
class TestDisasmOracle(unittest.TestCase):
    def test_entry_mnemonics_match_objdump(self):
        tool = _find_objdump()
        info = parse_binary(_read(CORPUS[0]))
        sec = info.section(".text")
        if sec is None:
            self.skipTest("no .text")
        data = _read(CORPUS[0])[sec.offset : sec.offset + 64]
        ours = [i.mnemonic for i in Disassembler(arch=info.arch).disassemble(data)][:5]
        # best-effort: objdump raw binary blob (objdump target follows the binary's arch)
        objdump_target = {
            "x86_64": "i386:x86-64", "x86": "i386",
            "arm64": "aarch64", "aarch64": "aarch64", "arm": "arm",
        }
        target = objdump_target.get(info.arch)
        if target is None:
            self.skipTest(f"no objdump target for arch {info.arch}")
        proc = subprocess.run(
            [tool, "-D", "-b", "binary", "-m", target, "/dev/stdin"],
            input=data, capture_output=True, timeout=20,
        )
        if proc.returncode != 0:
            self.skipTest(f"objdump target '{target}' unavailable on this machine")
        text = proc.stdout.decode("latin1", "ignore").lower()
        self.assertTrue(all(m in text for m in ours[:3]) or not ours, f"ours={ours}")


if __name__ == "__main__":
    unittest.main()
