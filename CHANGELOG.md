# Changelog

All notable changes to this project are documented here.

## [0.4.1] - 2026-09-03

Weights are now measured, not tabled. A fixed weight per claim kind invited the next
gaming move (an 8-byte `bytes_at` on zero padding verified at full weight).

### Changed

- **Measured surprisal**: for content claims (`bytes_at`, typed reads, `instructions`,
  `pattern_present`, `string_present`) the weight is driven by `evidence.weight_basis` —
  how often the expected content occurs in *this* binary and its normalized entropy — so
  zero padding, a ubiquitous prologue, or a pattern that matches hundreds of places weigh
  almost nothing even though they verify. `emulate_result` must actually execute (steps)
  over non-degenerate code (entropy); emulating padding weighs zero. Structural kinds keep
  a fixed tier until corpus base rates exist.
- The prompt no longer tells the model to re-assert observed values (which the echo rule
  correctly scores zero); it says to build *new* claims from them. Shift-signal caution is
  labelled as a heuristic.
- `reconstruct --mock` picks its demo window by entropy instead of taking the file tail.
- CLI prints the weight basis next to each verdict. 5 new tests (133 total).

## [0.4.0] - 2026-09-03

The loop is now hard to game. A verifier that only checks what the model asserts can be
satisfied with trivia; this release scores what the verified set actually *says* and closes
the channels a model uses to look grounded without being informative.

### Added

- **Information-weighted scoring** (`verifier.summarize`): every result carries a `weight`;
  zero for claims that restate the fact sheet, duplicates, self-referential inline code/data,
  and echoes of the tools' previous output; otherwise a surprisal tier by kind/specificity.
  Reports expose `information`, `grounded_score`, `trivial_verified`, and `grounded` =
  trustworthy **and** informative (`--min-information`). Follows CORE (Jiang et al., 2024).
- **Address spaces**: claims accept `"space": "file" | "rva" | "va"`; the verifier translates
  via the section table (`BinaryInfo.rva_to_offset/va_to_offset/offset_to_rva`) and echoes all
  three in `evidence.address`. Refuted `bytes_at`/typed reads report
  `nearest_offset_of_expected`.
- **Typed reads** `u16_at` / `u32_at` / `u64_at` (`endian: le|be`) so the model never does
  endianness or width arithmetic.
- **OBSERVED verdict**: `"observe": true` (or a missing `expected`) makes the tools report a
  value instead of judging one; the agent folds observed values into the next round's facts.
- **Dependencies**: claims carry `id` / `depends_on`; a refuted root marks its dependents
  `INVALIDATED`.
- **`instructions` operands** are compared when supplied; **`emulate_result`/`protobuf_field`**
  prefer `offset` into the binary, and inline `code`/`data` not found in the binary is flagged
  `self_referential` (weight 0).
- **Agent hardening**: keyed/addressed fact sheet with section address table and
  distribution-shift signals (per-section entropy, import count, entry section, overlay,
  packed-likely); echo detection; attrition per round; `samples` per round with the verifier
  as selector; proposer temperature 0.7 by default; the ineffective "only propose what you
  believe" instruction replaced by scoring rules the model can act on.
- CLI: `verify --min-information`; `reconstruct --samples/--min-information/--temperature`;
  notes are rendered as `note (unverified)` and never inline with a verdict.
- 32 new tests (128 total).

### Fixed

- **Pure-Python PE parser layout bugs**: PE32+ `BaseOfCode` was read as 8 bytes (shifting
  `ImageBase` and every field after it), and the PE32 format string was one dword short, so
  pure mode crashed on every 32-bit Windows binary. Both layouts now match the spec and are
  pinned by tests on both backends; `parse_binary` degrades to an error field instead of
  raising on malformed headers.

## [0.3.0] - 2026-09-03

Mature engines replace the hand-rolled internals — when installed.

### Added

- **Optional mature backends** (`reverify/backends.py`): the toolkit auto-detects and uses
  **capstone** (disassembly), **unicorn** (real CPU emulation) and **lief** (PE/ELF/Mach-O
  parsing) when present, and falls back to the pure-Python core otherwise. `reverify backends`
  and the `re_backends` MCP tool report what is active. Install with `pip install "reverify[full]"`.
- **Unified binary parsing** (`reverify/binary.py`): one `parse_binary()` / `BinaryInfo` covering
  PE, ELF and Mach-O with sections, imports, exports and linked libraries. New `reverify parse`
  command and `re_parse` MCP tool.
- **`UnicornEmulator`**: real emulation across x86, x86_64, ARM and ARM64 (every instruction,
  not a handful). `make_emulator()` picks Unicorn when available; `emulate` gains `--backend`.
- **New verifier claim kinds**: `import_present` (PE/ELF/Mach-O; `pe_import` kept as an alias),
  `export_present`, and `section_present`.
- 21 new unit tests (96 total), gated so the suite passes with or without the engines installed.

### Changed

- Auto-triage, the verifier, the reconstruction agent and the MCP server now go through the
  unified parser and emulator, so they gain ELF/Mach-O and multi-arch support automatically.
- `pyproject.toml` extras: `capstone`, `unicorn`, `lief`, and `full`.

## [0.2.0] - 2026-09-02

The verification loop is now closed: the model drives the tools automatically.

### Added

- **Closed reconstruction loop (`reverify/agent.py`)** — `ReconstructionAgent`
  asks a language model to propose claims about a binary, verifies every claim
  with the deterministic `Verifier`, feeds the refutations and their observed
  evidence back, and iterates until the reconstruction is grounded or a round
  cap is hit. The model proposes; the bytes decide.
- `reverify reconstruct <target> --goal "..."` CLI command, with `--mock` for an
  offline demo and `--rounds` to cap iterations. Exits non-zero if not grounded.
- The language model is injected as a `propose` callable, so the loop is fully
  testable offline; `openai_proposer()` builds a default from `OPENAI_*` env.
- 11 new unit tests for the loop (75 total).

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
