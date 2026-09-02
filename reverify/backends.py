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


def backend_report() -> Dict[str, Any]:
    """Which engine each subsystem is using right now."""
    return {
        "disassembly": {"engine": "capstone" if HAS_CAPSTONE else "pure-python", "version": CAPSTONE_VERSION},
        "emulation": {"engine": "unicorn" if HAS_UNICORN else "pure-python", "version": UNICORN_VERSION},
        "binary_parsing": {"engine": "lief" if HAS_LIEF else "pure-python", "version": LIEF_VERSION},
        "full_fidelity": HAS_CAPSTONE and HAS_UNICORN and HAS_LIEF,
        "install_hint": None if (HAS_CAPSTONE and HAS_UNICORN and HAS_LIEF) else 'pip install "reverify[full]"',
    }
