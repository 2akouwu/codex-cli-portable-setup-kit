"""Backend detection: mature engines when installed, pure Python otherwise.

Reverify keeps a pure-Python core so ``pip install reverify`` always works. When
the battle-tested engines are present the toolkit upgrades itself automatically:

- **capstone** — full-fidelity disassembly for x86/x64/ARM/ARM64.
- **unicorn**  — real CPU emulation (every instruction, every listed arch).
- **lief**     — PE, ELF and Mach-O parsing with imports/exports/sections.

Install them all with ``pip install "reverify[full]"``.
"""

from __future__ import annotations

from typing import Any, Dict

try:
    import capstone  # noqa: F401
    HAS_CAPSTONE = True
    CAPSTONE_VERSION = getattr(capstone, "__version__", "?")
except Exception:  # pragma: no cover
    HAS_CAPSTONE = False
    CAPSTONE_VERSION = None

try:
    import unicorn  # noqa: F401
    HAS_UNICORN = True
    UNICORN_VERSION = getattr(unicorn, "__version__", "?")
except Exception:  # pragma: no cover
    HAS_UNICORN = False
    UNICORN_VERSION = None

try:
    import lief  # noqa: F401
    HAS_LIEF = True
    LIEF_VERSION = getattr(lief, "__version__", "?")
    try:
        lief.logging.disable()
    except Exception:
        pass
except Exception:  # pragma: no cover
    HAS_LIEF = False
    LIEF_VERSION = None

try:
    import z3  # noqa: F401
    HAS_Z3 = True
    Z3_VERSION = z3.get_version_string()
except Exception:  # pragma: no cover
    HAS_Z3 = False
    Z3_VERSION = None

try:
    import importlib.util as _ilu
    HAS_ANGR = _ilu.find_spec("angr") is not None  # do not import: angr takes seconds to load
    ANGR_VERSION = None
    if HAS_ANGR:
        try:
            from importlib.metadata import version as _pkg_version
            ANGR_VERSION = _pkg_version("angr")
        except Exception:
            ANGR_VERSION = "?"
except Exception:  # pragma: no cover
    HAS_ANGR = False
    ANGR_VERSION = None


def backend_report() -> Dict[str, Any]:
    """Which engine each subsystem is using right now."""
    return {
        "disassembly": {"engine": "capstone" if HAS_CAPSTONE else "pure-python", "version": CAPSTONE_VERSION},
        "emulation": {"engine": "unicorn" if HAS_UNICORN else "pure-python", "version": UNICORN_VERSION},
        "binary_parsing": {"engine": "lief" if HAS_LIEF else "pure-python", "version": LIEF_VERSION},
        "proof": {"engine": "z3" if HAS_Z3 else "none", "version": Z3_VERSION},
        "semantic": {"engine": "angr" if HAS_ANGR else "pure-python", "version": ANGR_VERSION,
                     "note": None if HAS_ANGR else 'function boundaries, call graph and xrefs need pip install "reverify[angr]"'},
        "full_fidelity": HAS_CAPSTONE and HAS_UNICORN and HAS_LIEF,
        "install_hint": None if (HAS_CAPSTONE and HAS_UNICORN and HAS_LIEF) else 'pip install "reverify[full]"',
    }
