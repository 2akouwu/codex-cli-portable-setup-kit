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
