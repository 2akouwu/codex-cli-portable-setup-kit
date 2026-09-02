# Changelog

All notable changes to this project are documented here.

## [0.1.0] - 2026-09-02

The core idea of the project — verification — is now implemented.

### Added

- **Tool-grounded claim verifier (`reverify/verifier.py`)** — the heart of Reverify. A
  hypothesis about a binary is checked against the actual bytes with the deterministic
  toolkit and returned as `VERIFIED` / `REFUTED` / `INCONCLUSIVE`, always with the observed
  evidence. Seven claim kinds: `bytes_at`, `pattern_present`, `string_present`,
  `instructions`, `emulate_result`, `protobuf_field`, `pe_import`.
- `reverify verify` CLI command (single claim, batched `--claims-file`, non-zero exit on any
  refutation so agents and CI can gate on a grounded reconstruction).
- `re_verify_claim` MCP tool, so agents can have their own hypotheses judged before reporting.
- `pyproject.toml` packaging with `reverify` and `reverify-mcp` console scripts, and an
  optional `[capstone]` extra.
- 27 new unit tests covering the verifier (64 total after the removal below).

### Changed

- CLI and MCP server now import cleanly both as installed package and as direct scripts.

### Removed

- The `reverify/pipeline/` narrative-generation scaffold and its `pipeline` CLI command.
  It was unrelated to reverse engineering and is not part of the toolkit's purpose; the
  RE tools, verifier, and MCP server never depended on it.

## [0.0.0] - 2026-09-02

Initial public groundwork.

### Added

- `reverify` core: a pure-Python reverse-engineering toolkit — PE32/PE32+ parsing,
  x86/x64 disassembly, AOB pattern scanning, CPU micro-emulation, Protobuf/TLV protocol
  dissection, Frida hook generation, and a defensive filesystem/SSRF boundary auditor.
- Unified CLI (`reverify/cli.py`) and an MCP server (`reverify/mcp_server.py`) that exposes
  the toolkit to AI agents such as Claude Code and Cursor.
- Dual-stage decoupled pipeline scaffold (`reverify/pipeline/`) — the basis for the planned
  tool-grounded verification loop.
