# Benchmark: does the verifier catch a real hallucination, safely?

Reproducible: `python benchmarks/prologue_prior.py` (needs real binaries on disk
plus capstone + lief; defaults to Windows System32 / SysWOW64).

## What it measures

A language model asked what a function's entry prologue looks like tends to answer
the textbook frame-pointer prologue `push rbp ; mov rbp, rsp`. This benchmark
applies that prior **blind** — it never reads the disassembly itself — to a corpus
of real system DLLs and measures, purely through reverify's verifier:

| metric | meaning |
|---|---|
| **prior wrong** | how often the model's textbook prologue is a hallucination |
| **false VERIFIED** | how often a *wrong* claim was accepted — the safety failure, must be 0 |
| **grounded after 1 round** | the loop re-states the mnemonics the verifier reported, reaching the true bytes |

## Result (one run, 19 real DLLs: 9 x64 System32, 10 x86 SysWOW64)

```
prior wrong (hallucination rate): 19/19 = 100%
false VERIFIED (must be 0)       : 0
true bytes after 1 feedback round: 19/19 = 100%
```

Every binary's real entry prologue was something other than `push; mov` — the x64
ones open by saving a register to shadow space (`mov [rsp+8], rbx ; push rdi ;
sub rsp, N`), the x86 ones with the `mov edi, edi` hot-patch stub. The textbook
prior was wrong every time, the verifier refuted every one, and **it never once
marked a wrong claim VERIFIED**.

## Reading it honestly

- The meaningful result is the first two rows: a real, common model hallucination
  is caught with **zero false accepts** on real binaries. The zero-false-accept
  property is the verifier's soundness (tested independently in
  `tests/test_oracle.py` / `test_differential.py`), confirmed here in the field.
- "100% wrong" is specific to **entry-point** prologues, which are CRT/DLL startup
  stubs with characteristic non-textbook shapes. Random internal functions would
  give a different rate; this is one clean probe of one well-known prior, not a
  survey of all hallucinations.
- "grounded after 1 round" shows the feedback loop converging to the true bytes,
  but round 2 restates what the tool reported — in the scored `reconstruct` loop
  that restatement is echo-detected and carries no information weight. It proves
  the loop reaches ground truth; it is not the model independently reasoning.

The model here was Claude, plugged in as the injected proposer — no API key, no
specific model (see [EXAMPLE.md](EXAMPLE.md)).

## Multi-prior hallucination scorecard (`hallucination_probes.py`)

Reproducible: `python benchmarks/hallucination_probes.py [dir ...] [--per-dir N]
[--probe name ...]` (defaults to Windows System32 / SysWOW64, else /usr/bin +
/usr/lib). It extends the single-probe script above into a **scorecard** over
several model priors that reflect real LLM hallucination patterns, each applied
blind and measured through the verifier with a per-probe false-VERIFIED guard.

| probe | prior it probes | applicability |
|---|---|---|
| `prologue` | textbook frame-pointer prologue at the entry | x86 / x86_64 |
| `md5_const` | "this is MD5" — MD5 initial constant A0 (0x67452301) present | x86 / x86_64 (constant appears as a contiguous 32-bit LE immediate; on AArch64 it is split by movz/movk, so the byte pattern is not a sound prior) |
| `import_gets` | the program uses the deprecated C `gets()` | PE / ELF / Mach-O |
| `section_rodata` | a section named `.rodata` (an ELF name applied to PE, which uses `.rdata`) | PE / ELF / Mach-O |

Per probe the scorecard reports **prior wrong** (the hallucination rate — how
often the blind prior is refuted), **prior right**, **inconclusive**, and the
global **false VERIFIED** count, which must be 0. A VERIFIED verdict is
re-checked against the raw bytes / parse (bypassing the verifier) so a wrong
accept is caught, not trusted.

## Result (one run, 8 real arm64 ELFs under /usr/bin)

```
probe           prior wrong   false VERIFIED (must be 0)
prologue        0/8          0   (skipped: x86-family only)
md5_const       0/8          0   (skipped: x86-family only)
import_gets     8/8 = 100%   0
section_rodata  0/8 = 0%     0   (.rodata is a real ELF section, prior is right)
global false VERIFIED (must be 0): 0
```

`import_gets` is a clean field confirmation: none of the system ELFs import the
deprecated `gets`, the prior is refuted every time, and the guard never once
accepted a wrong claim. The x86-only probes (`prologue`, `md5_const`) are
exercised on the Windows corpus above and in `tests/test_probes.py` (synthetic
PE/ELF fixtures pin the guard logic without needing a real binary corpus).

## Regression test

`tests/test_probes.py` builds a synthetic PE32+ and a minimal ELF and pins the
guard logic: a VERIFIED verdict whose evidence contradicts the claim must be
flagged as a false accept (this is where an earlier draft of the prologue guard
was inverted), while a genuinely consistent VERIFIED is not. Run with
`python -m pytest reverify/tests/test_probes.py`.
