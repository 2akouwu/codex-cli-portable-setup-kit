# Changelog

All notable changes to this project are documented here.

## [0.10.0] - 2026-09-04

Evidence at top spec. Numbers used to be run on the author's Windows machine and typed
into a document; now the benchmark runs in CI on each platform's own binaries, leaves a
record with hashes and tool versions, and fails the build on a single false VERIFIED.
The first CI run also caught what a maintainer machine with everything installed never
could: the pure decoder was refuting correct claims.

### Added

- **Benchmark as evidence**: `benchmarks/prologue_prior.py --json` writes a machine-readable
  record (per binary: SHA-256, size, format, arch, entry, verdicts; environment: reverify,
  Python, platform, engines; totals with a 95% Wilson upper bound on the false-VERIFIED
  rate), `--markdown` renders it, `--fail-on-false-verified` makes it a gate. Per-platform
  default corpora (Windows System32/SysWOW64, Linux /usr/bin + multiarch /usr/lib, macOS
  /bin + /usr/bin), deterministic sampling. CI runs it on Linux, Windows and macOS on every
  push and uploads the record; reference runs are committed under `benchmarks/results/`.
- **Verdict receipts**: every `verify_all` report (CLI `--json`, MCP `re_verify_claim`)
  carries `receipt` — binary SHA-256 and size, reverify version, Python, platform, which
  engine judged each subsystem, timestamp, replay command.
- **Cross-platform judges**: the differential/oracle corpus now includes Linux ELF and
  macOS Mach-O system binaries (the pure ELF reader is header-only and is compared on
  headers; Mach-O has no pure reader and is skipped honestly), so `objdump` judges the
  disassembler on Linux CI and the parser differential runs on all three platforms.
- **Nightly fuzz** (`.github/workflows/fuzz.yml`): the robustness and soundness properties
  over 20,000 malformed inputs (`REVERIFY_FUZZ_N`).

### Fixed

- **Pure decoder never refutes on bytes it cannot decode.** In pure mode (no capstone)
  an `instructions` claim whose window contains bytes the fallback does not understand
  is now `INCONCLUSIVE` with an install hint — not `REFUTED` (and never `VERIFIED`).
- **Pure decoder understands the common x64 forms**: the REX prefix is consumed as part
  of the instruction (`48 89 e5` is `mov rbp, rsp`, r8–r15 named), `push`/`pop` use
  64-bit registers in long mode (`push rbp`, not `push ebp`), register-direct
  `mov`/`add`/`sub`/`xor` decode, and **memory forms are left as `db` instead of being
  misread as register forms** (a real mis-decode of `mov eax, [rbp-8]` before). Every byte
  is still accounted for.

### Added

- **CI** (`.github/workflows/ci.yml`): Linux, Windows and macOS × Python 3.9 and 3.13 with
  nothing installed, plus Python 3.13 with the engines, aggregated into one required check;
  a weekly/on-demand angr job; a tag-triggered release workflow that publishes to PyPI via
  Trusted Publishing; Dependabot for Actions pins only.
- **Zero-ceremony contributing**: no CLA, no sign-off, no issue-first rule, no checklist;
  squash merges; CI runs the matrix so contributors don't have to.

## [0.9.1] - 2026-09-04

### Fixed

- **ARM64 was disassembled as x86_64** (PR #5 by @IMGillusion, found by running the
  prologue benchmark on an aarch64 Jetson): `disasm.py` picked the x86_64 capstone decoder
  on `"64" in arch`, which is also true for `arm64` / `aarch64`. The ARM branches now come
  first; `benchmarks/prologue_prior.py` honors the parsed `info.arch`; the objdump oracle test
  picks its target from the arch and skips when it is absent. Regression tests pin the
  routing. BENCHMARK.md gains the aarch64 Linux ELF result: prior wrong 19/19, false
  VERIFIED 0, true bytes after one feedback round 19/19 (11% before the fix).
- **Soundness without the engines**: the pure-Python decoder and micro-emulator are
  x86/x64 only. They used to run ARM/MIPS/... bytes anyway and produce junk a wrong claim
  could match — a possible false VERIFIED in pure mode. `instructions` and `emulate_result`
  on a non-x86 arch now return `INCONCLUSIVE` with an install hint when capstone / unicorn
  are missing (`UnsupportedArch`, `EmulatorError`). 4 new tests.

## [0.9.0] - 2026-09-04

The semantic layer (roadmap issue #3). Bytes, instructions, imports and emulation
are what the deterministic core can judge on its own; the claims analysts actually
make — *function X calls Y*, *this string is referenced from that routine*, *this
code is reachable from the entry point* — need function boundaries and
cross-references, i.e. a real program-analysis engine. Reverify does not build one:
it stands on **angr** (`CFGFast`) and keeps its own part thin.

### Added

- **`reverify/semantic.py`**: an engine-neutral `SemanticView` (functions, call edges,
  data cross-references, reachability from the entry point; all addresses as RVAs)
  built by angr when installed (`pip install "reverify[angr]"`, cached per content
  hash so a long-lived MCP server pays for the CFG once). Without an engine the
  **pure fallback only knows what is independently certain** — the entry point and the
  exports are function starts — and everything else is `INCONCLUSIVE`, never a guess.
- **Four claim kinds**: `function_at` (offset or name; `observe` reads size, blocks,
  callees), `calls` (`from` -> `to`, where `to` may be a function or an import name;
  a refutation lists the real callees), `references` (code references the data at
  `to`, e.g. a string, optionally from a given function; a refutation lists the
  referencing functions) and `reachable_from_entry`. Addresses accept
  `space: file|rva|va` like every other claim; names accept `lib!func`.
- **Honest strength**: semantic verdicts carry `engine`/`engine_version` and are
  recorded in the ledger at a new **`DERIVED`** tier — recovered by static analysis,
  not read from the bytes — below `VERIFIED`; CFGFast is heuristic and the evidence says
  so. The ladder is now proven > tested > verified/derived > observed.
- **Who verifies the verifier, semantic edition**: the export table (lief or the pure
  parser, independent of angr) is the oracle — every export must be a function start the
  engine recovered (`test_exports_are_function_starts_differential`).
- `BinaryInfo.export_rvas` (name -> RVA, forwarders excluded) from lief and the pure PE
  parser; `reverify backends` reports the semantic engine; MCP tool **`re_semantic`**
  (`summary|functions|function_at|callees|callers|references|reachable`); CLI
  **`reverify functions <file>`**; `pyproject` extra `[angr]` (large; deliberately not
  part of `[full]`).
- 12 new tests (208 total), gated: the pure-fallback tests always run, the angr tests run
  when the engine is installed (verified on Python 3.12 with angr 9.3.4 and, without
  angr, on Python 3.14).

## [0.8.0] - 2026-09-04

Lossless context rollover. Every agent harness compacts a full context window
the same way — a model summarizes the transcript and the rest is dropped — and
every one of them documents the loss. Reverify's loop can avoid it, because it
already knows which part of the transcript is *state*: what the tools verified,
observed, proved, and refuted. That is now written to disk as it happens, so a
context can be cleared, compacted or restarted and the next round continues from
the same grounded position. Nothing the model said on its own was ever trusted,
so nothing is lost by dropping it.

### Added

- **`reverify/ledger.py` — durable per-binary ledger** (`.reverify/ledger/<sha256>.json`,
  override with `REVERIFY_LEDGER_DIR`): grounded results only (VERIFIED with weight,
  OBSERVED values, the `behavior_equiv` TESTED and `prove_equiv` PROVEN tiers) plus
  refutations as **known-false**, keyed by claim, de-duplicated, atomic writes, corrupt
  files quarantined instead of fatal. Claim notes (unverified text) are never stored.
- **Bounded projection, unbounded store**: `established(max_facts)` shows the most recent
  facts with proof/test-tier facts pinned so they never page out; the disk keeps everything.
- **`ReconstructionAgent(ledger=..., resume=True, prompt_budget=60000, file_path=...)`**:
  checkpoints the ledger after every round (a crash mid-run loses nothing), resumes from
  whatever the ledger holds, and shows KNOWN FALSE so a fresh context does not re-propose
  the same wrong prior. A claim already in the ledger scores zero (`known`) — resuming
  cannot be farmed for information. `run()` now reports `resumed_facts`, `compactions`,
  `over_budget`, `ledger`, `ledger_path`, per-round `prompt_chars` and `compaction`.
- **Prompt budget (`compact_facts`)**: a deterministic ladder trims the fact sheet *shown*
  to the model (long import lists, strings, old observed values) until the prompt fits;
  scoring still uses the full sheet, so hiding a fact never makes restating it profitable.
  kernel32.dll: 43k-char prompt fits a 20k budget with the section table, entry point and
  header intact.
- **MCP**: `re_verify_claim` records grounded results automatically (`record`, `goal`,
  `session` params; replies carry `ledger` counts and `known=true` on repeats); new
  **`re_ledger`** tool (`show` / `index` / `clear`, `max_facts`) restores the state after
  the host's own compaction or `/clear`; server `instructions` tell any MCP host to do so;
  `reverify://ledger/<sha>` **resources**; JSON-RPC notifications no longer get error replies;
  `ping`; real version in `serverInfo`.
- **CLI**: `reverify ledger [target] [--context [--full]] [--hook] [--clear] [--json]` and
  `reconstruct --ledger/--no-ledger/--fresh/--max-facts/--prompt-budget/--session`.
  `reverify ledger --hook` prints a Claude Code `SessionStart` hook (`compact|clear|resume`)
  that re-injects a **one-line index per binary** — the hand-off costs a few dozen tokens
  and the facts are pulled on demand.
- 20 new tests (196 total): round-trip and atomicity, content-keyed ledgers, tiers and
  pinning, corrupt-file quarantine, lossless resume with negative memory, crash-safe
  per-round checkpoints, budget ladder trims the view only, full-sheet scoring on a real PE,
  MCP record/restore/clear and stdio protocol, CLI hand-off and hook.

### Changed

- `summarize()` zeroes the weight of results flagged `known`; the report counts them.
- `RULES` now say restating ESTABLISHED scores zero as well.

## [0.7.1] - 2026-09-04

### Added

- **Bounded reconstruction ledger** (`ReconstructionAgent(max_facts=...)`, default 40): the
  established-facts ledger is capped, so a long run does not turn its own accumulated context
  into a fresh source of drift. Dropped facts were verified true and can be observed again if
  needed — long-session hygiene for the loop itself. 177 tests.

## [0.7.0] - 2026-09-04

A proof tier. Behavioral equivalence by sampling says "no counterexample found over N
inputs"; a solver says "no counterexample exists". This adds the second.

### Added

- **`prove_equiv` claim kind** (Z3): proves two integer expressions equal for **all**
  inputs over bit-vector logic, or refutes with a distinguishing input. Verifies that an
  obfuscated expression simplifies correctly — Mixed Boolean-Arithmetic (MBA)
  deobfuscation — e.g. `(x^y) + 2*(x&y)` is proven equal to `x + y` for every 64-bit
  input, and `x^y == x+y` is refuted with a concrete counterexample. Proof-grade weight;
  a trivial identity (`a` == `b`) scores zero.
- `reverify.prove_expr_equiv()` and a safe expression-to-Z3 compiler (whitelisted AST).
- **Z3 as an optional backend**: `pip install "reverify[z3]"` (or `[full]`). Without it the
  claim returns INCONCLUSIVE. `reverify backends` / `re_backends` report the proof engine.
- 8 new tests (176 total), gated so the suite passes with or without Z3.

This puts a genuine PROVEN tier above the sampled `behavior_equiv` — the honest strength
ladder: proven > tested > observed.

## [0.6.0] - 2026-09-04

Fights context hallucination — the model building on its own earlier guesses, or
misremembering a value from a long context. The reconstruction loop is now two-stage
(observe, then hypothesize) with a memory that only holds grounded facts.

### Added

- **Established-facts ledger** in `ReconstructionAgent`: after each round, only results
  the tools actually grounded — claims that VERIFIED with weight, and values the tools
  OBSERVED — enter the ledger. The model's own unverified claims are **never carried
  forward**. Each round the model is shown BINARY FACTS + ESTABLISHED and told to build
  only on those; anything it proposed earlier that isn't established "did not happen".
  This is the direct defense against a model citing its own prior hallucination, and
  against long-context misremembering (it observes fresh instead of recalling).
- **Two-stage prompt (plan then ground)**: each round the model first OBSERVEs what it
  needs but doesn't know (the tools read it, and it becomes established), then
  HYPOTHESIZEs new checkable claims — separating "what to investigate" (the model's
  strength) from "what is true" (the tools' job).
- `run()` returns the `established` ledger; the ledger is de-duplicated and order-stable.
- 5 new tests (168 total), including that a refuted hallucination and its editorial note
  are never carried into the next round's prompt.

## [0.5.0] - 2026-09-03

Execution as judge. The strongest form of grounding: verify a reconstruction of a function
by *running it*, not by reading it — the methodology behind executable decompilation
benchmarks (ExeBench I/O pairs, LLM4Decompile's re-executability).

### Added

- **Behavioral-equivalence verifier** (`reverify/behavior.py`) and the `behavior_equiv`
  claim kind. The original function (from an `offset` into the binary, or inline `code`) and
  a candidate (a restricted integer `expr` over `x0, x1, ...`, or `candidate_code` hex) are
  run over shared boundary + pseudo-random inputs and their outputs compared. A mismatch
  returns a **concrete counterexample input** ("differs at x = ..."); agreement is reported
  honestly as "equivalent over N inputs (tested, not proven)". Self-contained computational
  functions only; anything that faults or calls out returns INCONCLUSIVE.
- Runs on Unicorn with a configurable register calling convention (x86-64 System V by
  default). No compiler or model needed to verify. Inline `code` originals are flagged
  self-referential (weight 0); offset-based originals earn weight scaled by inputs tested and
  code entropy — behavioral equivalence is the highest-weighted claim.
- Safe integer expression evaluator (`eval_expr`): whitelisted AST, no calls/attributes.
- CLI renders the counterexample on a refuted behavioral claim. 163 tests.

### Notes

- This is the reverify-side of the standard executable-decompilation metric; an ExeBench /
  LLM4Decompile adapter (compile candidate C, re-run against I/O pairs) is the next step and
  is gated on a C compiler being present.

## [0.4.2] - 2026-09-03

Who verifies the verifier. A verification tool whose own reading of a binary is only
checked by hand-written tests shares the author's blind spots — the pure PE parser and its
synthetic fixture were wrong the same way, so the fixture passed. This release cross-checks
the readers the way mature tools do (Csmith, cryptofuzz, RISU, NIST/Wycheproof vectors), and
ships the bugs that found.

### Added

- **Differential + fuzz testbed** (`tests/test_differential.py`): the pure-Python parser vs
  lief over real x64 (System32) and x86 (SysWOW64) binaries — headers, arch, image base,
  entry, section RVAs must agree, and the pure parser must never invent a named import lief
  lacks; file<->rva<->va and observe->assert round-trips; malformed input never raises, never
  warns, never yields a false VERIFIED; soundness — `bytes_at` verifies iff the bytes match.
- **Cross-engine oracle + KAT** (`tests/test_oracle.py`): hand-verified instruction
  known-answer vectors (ground truth external to both engines); the pure decoder vs capstone
  on the opcode subset it implements; the pure `MicroEmulator` vs Unicorn (run the same code
  in two engines, compare registers — RISU-style); random bytes into the disassembler and
  emulator never raise or loop. 151 tests total.

### Fixed

- **MicroEmulator crashed on hostile code**: a wild `esp` followed by a `push` raised
  `EmulatorError` instead of faulting; `run()` now catches out-of-bounds memory and halts,
  as Unicorn does. Found by the fuzzer.
- **Pure disassembler dropped bytes**: a REX prefix was consumed without being counted, and a
  truncated `mov r, imm` advanced without emitting, so `sum(instruction sizes) != len`. The
  decoder now accounts for every byte. Found by the engine fuzz.
- **lief warning leak**: malformed ELF-magic input made lief's binding emit `RuntimeWarning`s;
  suppressed around the lief parse so hostile files degrade quietly.

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
