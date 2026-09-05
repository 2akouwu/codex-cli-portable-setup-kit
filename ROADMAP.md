# Roadmap — toward the reference standard for grounded AI reverse engineering

reverify's two moats are **(1) a benchmark others measure against** and **(2) a
zero-false-accept guarantee hardened enough that people trust it**. Everything
below serves one of those. Ordered by leverage. Check items off in PRs.

## 1. Make the benchmark the thing people cite  · *highest leverage*

The prologue-prior scorecard and the verifier confusion matrix are the seed; the
goal is numbers an outside researcher reproduces and quotes.

- [x] **Re-executability adapter** for standard datasets (ExeBench / LLM4Decompile
  shape): `benchmarks/reexec_dataset.py` compiles each candidate and re-runs it
  against recorded I/O through the `exebench` path, reports the re-exec rate and a
  false-accept gate (a labeled-wrong candidate must be refuted). Bundled sample
  corpus + tests.
- [ ] Run it against the **published LLM4Decompile / ExeBench test sets** and record
  the numbers in `BENCHMARK.md` with dataset hashes and tool versions.
- [ ] Expand the hallucination scorecard to a **labeled multi-class corpus** across
  PE / ELF / Mach-O and x86/x64/ARM64 (in progress: `prologue`, `md5_const`,
  `import_gets`, `section_rodata`, `elf_shoff`).
- [ ] **Baseline deltas**: report false-accept rate of raw LLM vs LLM+reverify on the
  same corpus, so the improvement is a number, not a claim.
- [ ] A short **methodology write-up** (arXiv / docs): proposer–verifier for RE, the
  zero-false-accept property, how the corpus is built and gated.

## 2. A second independent engine → differential verification

Today the semantic layer is angr alone. A gold-standard verifier makes two
independent engines *agree* before it says VERIFIED.

- [ ] **Ghidra headless** as a second CFG / function-boundary / decompiler source.
- [ ] Semantic claims (`function_at` / `calls` / `references`) require agreement
  between angr and the second engine; disagreement downgrades to INCONCLUSIVE,
  never VERIFIED. Turns the guarantee from "tested" into defense-in-depth.
- [ ] Report cross-engine agreement rate in the benchmark.

## 3. Harden native execution and the parsers  · *trust in real malware work*

- [x] **Sandbox for native execution** (`reverify/sandbox.py`): wall-clock timeout,
  CPU / memory / file-size / process-count limits, output cap, scrubbed env,
  isolated cwd; POSIX rlimits + a Windows Job Object. `exebench` compile and run
  now go through it, so opting in is reasonable on a normal box.
- [ ] Container recipe (rootless) for hostile corpora; document the threat model.
- [ ] Grow parser fuzzing (the PE/ELF/Mach-O readers parse attacker-controlled
  input): more corpora, longer runs, crash-repro fixtures in CI.

## 4. Meet reverse engineers where they already work

MCP + CLI reach agents; the humans live in disassemblers.

- [ ] **Ghidra / IDA / Binary Ninja plugin**: select a function, propose a claim,
  see VERIFIED / REFUTED with evidence in the tool.
- [ ] A **CI action** that verifies the claims in a repo's RE notes / detection
  rules and fails on a false VERIFIED.

## 5. Deeper claim kinds — and off binaries, toward verified coding

- [x] **`functions_equiv`**: differential execution of two implementations — compile a
  candidate and a reference, run over shared inputs, compare. The everyday "did this
  rewrite / the AI's version preserve behaviour?" check; the same rigour aimed at ordinary
  source code, not just binaries. First step of the verified-coding domain.
- [x] A real coding surface: a `reverify equiv` CLI and a **Python** runner (no toolchain, so it
  runs everywhere), alongside C.
- [ ] Grow it further: more languages (JS/Go/Rust), function-level (not just whole-program)
  contracts, spec-by-examples as the oracle.
- [ ] **Struct / type recovery**: verify a proposed layout against observed access
  patterns.
- [ ] **Path feasibility**: verify "input X reaches address Y" (build on angr's
  reachability).
- [ ] **More architectures**: RISC-V and MIPS (firmware / IoT targets).

## 6. Publish the verified-hand-off contract as a spec

The rollover / ledger hand-off (state in files, verified receipt, verbatim
anchors) is novel and cross-CLI. Writing it up as a spec lets other tools adopt
the receipt format instead of re-inventing lossy summaries.

- [ ] `SPEC-rollover.md`: the receipt schema, the fail-closed rules, the anchors.
- [ ] Reference the four supported CLIs (Claude Code / Codex / Gemini / OpenCode)
  and invite others to implement the same contract.
