#!/usr/bin/env python3
"""Compatibility shim: the rollover now lives in :mod:`reverify.rollover_harness` (all CLIs).

Hooks installed by earlier versions call ``claude_rollover.py stop`` / ``session-start``;
those still work and are routed to the Claude adapter. Everything else is re-exported.
"""
from __future__ import annotations

import os
import sys

_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.insert(0, _here)

from rollover_harness import *  # noqa: F401,F403,E402
from rollover_harness import (  # noqa: E402  (private names the tests use)
    _write_json, _read_json, _safe_name, _flag_value, main as _harness_main,
)


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    return _harness_main(argv)


if __name__ == "__main__":
    sys.exit(main())
