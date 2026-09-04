"""Unified binary parsing: PE, ELF and Mach-O through one interface.

Uses **lief** when installed (full imports/exports/sections for all three
formats). Falls back to the pure-Python PE parser and a minimal ELF header
reader otherwise, so the toolkit degrades gracefully instead of failing.
"""

from __future__ import annotations

import math
import struct
import warnings
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

try:  # package import
    from .backends import HAS_LIEF
    from .pe_parser import PEParser, BinaryParseError
except ImportError:  # flat import
    from backends import HAS_LIEF
    from pe_parser import PEParser, BinaryParseError


@dataclass
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    offset: int


@dataclass
class BinaryInfo:
    format: str                     # "PE" | "ELF" | "MachO" | "raw"
    arch: str = "unknown"           # x86 | x86_64 | arm | arm64 | unknown
    bits: int = 0
    entrypoint: Optional[int] = None
    image_base: Optional[int] = None
    sections: List[Section] = field(default_factory=list)
    imports: Dict[str, List[str]] = field(default_factory=dict)   # lib -> functions ("*" for ELF)
    exports: List[str] = field(default_factory=list)
    export_rvas: Dict[str, int] = field(default_factory=dict)  # export name -> RVA (function starts, independently known)
    libraries: List[str] = field(default_factory=list)            # linked libs (ELF/MachO)
    backend: str = "pure-python"
    error: Optional[str] = None

    # -- queries ----------------------------------------------------------

    def has_import(self, function: str, lib: Optional[str] = None) -> bool:
        for l, funcs in self.imports.items():
            if lib is not None and l.lower() != lib.lower():
                continue
            if function in funcs:
                return True
        return False

    def has_export(self, name: str) -> bool:
        return name in self.exports

    def section(self, name: str) -> Optional[Section]:
        for s in self.sections:
            if s.name == name:
                return s
        return None

    # -- address translation (file offset <-> RVA <-> VA) ----------------------
    #
    # Only *loaded* sections take part. ELF sections that are not mapped at run
    # time (.debug_*, .comment, .symtab, ...) all report virtual address 0, so
    # translating through them would map one file region onto another; they stay
    # in ``sections`` (so ``section_present`` still sees them) but never translate.

    def loaded_sections(self) -> List[Section]:
        return [s for s in self.sections if s.virtual_address != 0]

    def rva_to_offset(self, rva: int) -> Optional[int]:
        for s in self.loaded_sections():
            span = max(s.virtual_size, s.raw_size)
            if s.virtual_address <= rva < s.virtual_address + span:
                return s.offset + (rva - s.virtual_address)
        return None

    def offset_to_rva(self, off: int) -> Optional[int]:
        for s in self.loaded_sections():
            if s.offset <= off < s.offset + s.raw_size:
                return s.virtual_address + (off - s.offset)
        return None

    def va_to_offset(self, va: int) -> Optional[int]:
        if self.image_base is None:
            return None
        return self.rva_to_offset(va - self.image_base)

    def section_containing_rva(self, rva: int) -> Optional[Section]:
        for s in self.loaded_sections():
            if s.virtual_address <= rva < s.virtual_address + max(s.virtual_size, s.raw_size):
                return s
        return None

    def section_entropies(self, data: bytes) -> Dict[str, float]:
        """Shannon entropy (bits/byte) of each section's raw bytes."""
        out: Dict[str, float] = {}
        for s in self.sections:
            if s.raw_size > 0 and s.offset < len(data):
                out[s.name] = round(shannon_entropy(data[s.offset : s.offset + s.raw_size]), 3)
        return out

    def summary(self) -> Dict[str, Any]:
        return {
            "format": self.format,
            "arch": self.arch,
            "bits": self.bits,
            "entrypoint": hex(self.entrypoint) if self.entrypoint is not None else None,
            "image_base": hex(self.image_base) if self.image_base is not None else None,
            "sections": [s.name for s in self.sections],
            "imported_libs": list(self.imports.keys()),
            "import_count": sum(len(v) for v in self.imports.values()),
            "export_count": len(self.exports),
            "libraries": self.libraries,
            "backend": self.backend,
            **({"error": self.error} if self.error else {}),
        }

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["sections"] = [asdict(s) for s in self.sections]
        return d


def shannon_entropy(buf: bytes) -> float:
    """Shannon entropy in bits per byte (0..8). ~7+ suggests packed/encrypted data."""
    if not buf:
        return 0.0
    counts = [0] * 256
    for b in buf:
        counts[b] += 1
    n = len(buf)
    return max(0.0, -sum((c / n) * math.log2(c / n) for c in counts if c))


# -- arch mapping ---------------------------------------------------------

_PE_MACHINE = {"AMD64": ("x86_64", 64), "I386": ("x86", 32), "ARM64": ("arm64", 64), "ARMNT": ("arm", 32), "ARM": ("arm", 32)}
_ELF_MACHINE = {"X86_64": ("x86_64", 64), "I386": ("x86", 32), "AARCH64": ("arm64", 64), "ARM": ("arm", 32)}
_ELF_E_MACHINE = {62: ("x86_64", 64), 3: ("x86", 32), 183: ("arm64", 64), 40: ("arm", 32)}
_MACHO_CPU = {"X86_64": ("x86_64", 64), "X86": ("x86", 32), "ARM64": ("arm64", 64), "ARM": ("arm", 32)}


def _enum_name(value: Any) -> str:
    """'MACHINE_TYPES.AMD64' -> 'AMD64'; robust to plain strings/ints."""
    s = str(value)
    return s.rsplit(".", 1)[-1].upper()


# -- lief backend -----------------------------------------------------------

def _parse_with_lief(data: bytes) -> Optional[BinaryInfo]:
    import lief

    b = lief.parse(bytes(data))
    if b is None:
        return None

    fmt = _enum_name(b.format)
    if fmt == "PE":
        arch, bits = _PE_MACHINE.get(_enum_name(b.header.machine), ("unknown", 0))
        if bits == 0:
            bits = 64 if "PLUS" in _enum_name(b.optional_header.magic) else 32
        info = BinaryInfo(
            format="PE", arch=arch, bits=bits,
            entrypoint=int(b.optional_header.addressof_entrypoint),
            image_base=int(b.optional_header.imagebase),
            backend="lief",
        )
        for s in b.sections:
            info.sections.append(Section(s.name, int(s.virtual_address), int(s.virtual_size), int(s.size), int(s.offset)))
        for imp in b.imports:
            info.imports[imp.name] = [e.name for e in imp.entries if e.name]
        info.exports = [f.name for f in b.exported_functions if f.name]
        info.export_rvas = {
            f.name: int(f.address) for f in b.exported_functions
            if f.name and not getattr(f, "is_forwarded", False) and int(f.address) > 0
        }
        info.libraries = list(info.imports.keys())
        return info

    if fmt == "ELF":
        arch, bits = _ELF_MACHINE.get(_enum_name(b.header.machine_type), ("unknown", 0))
        if bits == 0:
            bits = 64 if "64" in _enum_name(b.header.identity_class) else 32
        info = BinaryInfo(
            format="ELF", arch=arch, bits=bits,
            entrypoint=int(b.entrypoint),
            image_base=int(getattr(b, "imagebase", 0)) or None,
            backend="lief",
        )
        for s in b.sections:
            info.sections.append(Section(s.name, int(s.virtual_address), int(s.size), int(s.size), int(s.offset)))
        funcs = [f.name for f in b.imported_functions if f.name]
        if funcs:
            info.imports["*"] = funcs
        info.exports = [f.name for f in b.exported_functions if f.name]
        info.export_rvas = {
            f.name: int(f.address) - (info.image_base or 0) for f in b.exported_functions
            if f.name and int(f.address) - (info.image_base or 0) > 0
        }
        info.libraries = list(getattr(b, "libraries", []) or [])
        return info

    if fmt in ("MACHO", "MACH_O"):
        # lief returns a FatBinary: prefer the slice that matches the host CPU so an
        # arm64 Mac judges its arm64 code (and CI on arm64 runners exercises it);
        # fall back to the first slice.
        m = b.at(0) if hasattr(b, "at") else b
        if hasattr(b, "at"):
            import platform as _platform
            host = _platform.machine().lower()
            want = "ARM64" if host in ("arm64", "aarch64") else ("X86_64" if host in ("x86_64", "amd64") else None)
            try:
                for cand in b:
                    if want and _enum_name(cand.header.cpu_type) == want:
                        m = cand
                        break
            except Exception:
                pass
        arch, bits = _MACHO_CPU.get(_enum_name(m.header.cpu_type), ("unknown", 0))
        info = BinaryInfo(
            format="MachO", arch=arch, bits=bits,
            entrypoint=int(m.entrypoint) if getattr(m, "has_entrypoint", False) else None,
            image_base=int(getattr(m, "imagebase", 0)) or None,
            backend="lief",
        )
        for s in m.sections:
            info.sections.append(Section(s.name, int(s.virtual_address), int(s.size), int(s.size), int(s.offset)))
        funcs = [f.name for f in m.imported_functions if f.name]
        if funcs:
            info.imports["*"] = funcs
        info.exports = [f.name for f in m.exported_functions if f.name]
        # __mh_execute_header & co. sit at the image base (relative address 0): symbols, not functions
        info.export_rvas = {
            f.name: int(f.address) - (info.image_base or 0) for f in m.exported_functions
            if f.name and int(f.address) - (info.image_base or 0) > 0
        }
        info.libraries = [l.name for l in getattr(m, "libraries", [])]
        return info

    return None


# -- pure-python fallbacks ------------------------------------------------

def _parse_pe_pure(data: bytes) -> BinaryInfo:
    p = PEParser(data)
    arch = "x86_64" if "x64" in (p.file_header.get("MachineName") or "") else (
        "arm64" if "ARM64" in (p.file_header.get("MachineName") or "") else "x86")
    info = BinaryInfo(
        format="PE", arch=arch, bits=64 if p.is_64bit else 32,
        entrypoint=p.optional_header.get("EntryPoint"),
        image_base=int(p.optional_header["ImageBase"], 16) if p.optional_header.get("ImageBase") else None,
        backend="pure-python",
    )
    for s in p.sections:
        info.sections.append(Section(s["Name"], s["RVA"], s["VirtualSize"], s["SizeOfRawData"], s["PointerToRawData"]))
    info.imports = {k: list(v) for k, v in p.imports.items()}
    info.exports = [e["name"] for e in p.exports]
    exp_dir = (getattr(p, "data_directories", {}) or {}).get("EXPORT") or (0, 0)
    for e in p.exports:
        rva = e.get("rva", e.get("address"))
        try:
            rva = int(str(rva), 16) if isinstance(rva, str) else int(rva)
        except (TypeError, ValueError):
            continue
        forwarded = exp_dir[0] <= rva < exp_dir[0] + exp_dir[1]  # an RVA inside the export directory is a forwarder string
        if e.get("name") and rva > 0 and not forwarded:
            info.export_rvas[e["name"]] = rva
    info.libraries = list(info.imports.keys())
    return info


def _parse_elf_pure(data: bytes) -> BinaryInfo:
    """Minimal ELF header reader: format/arch/bits/entry only."""
    if len(data) < 52:
        return BinaryInfo(format="ELF", backend="pure-python", error="ELF header truncated")
    is64 = data[4] == 2
    little = data[5] == 1
    end = "<" if little else ">"
    (e_machine,) = struct.unpack_from(end + "H", data, 18)
    if is64:
        (e_entry,) = struct.unpack_from(end + "Q", data, 24)
    else:
        (e_entry,) = struct.unpack_from(end + "I", data, 24)
    arch, bits = _ELF_E_MACHINE.get(e_machine, ("unknown", 64 if is64 else 32))
    return BinaryInfo(format="ELF", arch=arch, bits=bits, entrypoint=e_entry, backend="pure-python")


# -- entry point ------------------------------------------------------------

def parse_binary(data: bytes, prefer: str = "auto") -> BinaryInfo:
    """Parse ``data`` into a :class:`BinaryInfo`.

    ``prefer`` is ``"auto"`` (lief when available), ``"lief"`` (require it) or
    ``"pure"`` (force the pure-Python fallbacks).
    """
    if prefer == "lief" and not HAS_LIEF:
        raise RuntimeError("lief backend requested but not installed: pip install lief")

    if prefer in ("auto", "lief") and HAS_LIEF:
        try:
            # Malformed input makes lief's binding emit RuntimeWarnings from invalid
            # enum conversions; hostile/garbage files are expected here, so keep quiet.
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                info = _parse_with_lief(data)
            if info is not None:
                return info
        except Exception as exc:  # fall through to pure parsers
            if prefer == "lief":
                return BinaryInfo(format="raw", backend="lief", error=str(exc))

    if data[:2] == b"MZ":
        try:
            return _parse_pe_pure(data)
        except Exception as exc:  # malformed headers must degrade, never crash
            return BinaryInfo(format="PE", backend="pure-python", error=f"{type(exc).__name__}: {exc}")
    if data[:4] == b"\x7fELF":
        return _parse_elf_pure(data)
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return BinaryInfo(format="MachO", backend="pure-python", error="Mach-O needs lief: pip install lief")
    return BinaryInfo(format="raw", backend="pure-python")
