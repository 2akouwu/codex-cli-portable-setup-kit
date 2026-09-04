# Benchmark: does the verifier catch a real hallucination, safely?

**Replicate it yourself** (needs capstone + lief: `pip install "reverify[full]"`):

```bash
python benchmarks/prologue_prior.py --per-dir 40 --json my-run.json --fail-on-false-verified
```

It runs on your platform's own system binaries (Windows System32/SysWOW64, Linux
`/usr/bin` + multiarch `/usr/lib`, macOS `/bin` + `/usr/bin`), samples them
deterministically (sorted, fixed stride), and writes a record with the SHA-256 of every
file tested, every verdict, and the tool versions — so two people can compare runs file by
file. **CI runs exactly this on Linux, Windows and macOS on every push and fails the build
if a single wrong claim is VERIFIED**; each run's record is attached as an artifact
(`benchmark-<os>`) and the summary appears on the run page. Reference records are
committed under [`benchmarks/results/`](benchmarks/results/).

## What it measures

A language model asked what a function's entry prologue looks like tends to answer the
textbook frame-pointer prologue `push rbp ; mov rbp, rsp`. This benchmark applies that
prior **blind** — it never reads the disassembly itself — to real binaries and measures,
purely through reverify's verifier:

| metric | meaning |
|---|---|
| **prior wrong** | how often the model's textbook prologue is a hallucination on this corpus |
| **false VERIFIED** | how often a *wrong* claim was accepted — the safety failure, must be 0 |
| **true bytes after 1 round** | the loop re-states the mnemonics the verifier reported, reaching the true bytes |
| **95% upper bound** | Wilson interval on the false-VERIFIED rate: what "0 of N" does and does not prove |

## Results

### Windows 11, x86_64 + x86 (71 binaries, reference record)

Record: [`benchmarks/results/windows-x86_64-2026-09-04.json`](benchmarks/results/windows-x86_64-2026-09-04.json)
(reverify 0.10.0, Python 3.14, capstone + lief).

```
binaries tested                 : 71  (inconclusive, not counted: 0)
prior wrong (hallucination rate): 69/71 = 97%
false VERIFIED (must be 0)       : 0   (95% upper bound on the rate: 5.1%)
true bytes after 1 feedback round: 71/71 = 100%
```

Two of the 71 DLLs really do open with `push ; mov` and were *correctly* VERIFIED — the
metric is not rigged to make the prior look bad. The other 69 open with the x64 shadow-space
save (`mov [rsp+8], rbx ; push rdi ; sub rsp, N`) or the x86 hot-patch stub
(`mov edi, edi ; push ebp`), the verifier refuted every one, and it never once marked a wrong
claim VERIFIED.

### CI, three platforms (GitHub-hosted runners, not the author's machine)

Produced by [CI run 33871442164](https://github.com/2akouwu/reverify/actions/runs/33871442164)
on each runner's own system binaries; the full records (every file's SHA-256, every verdict)
are committed under `benchmarks/results/ci-*.json` and attached to every run as artifacts.

| platform (runner) | formats | tested | prior wrong | **false VERIFIED** | 95% upper bound | true bytes after 1 round |
|---|---|---|---|---|---|---|
| Linux x86_64 (ubuntu-latest) | ELF | 40 | 40 | **0** | 8.8% | 40/40 |
| macOS (macos-latest, universal binaries, x86_64 slice) | Mach-O | 77 | 77 | **0** | 4.8% | 77/77 |
| Windows Server (windows-latest) | PE x86 + x86_64 | 68 | 68 | **0** | 5.3% | 68/68 |

Across the reference run, the three CI runs and the third-party aarch64 run below: **275
binaries, 4 formats/architectures, 0 false VERIFIED** (pooled 95% upper bound about 1.4%).
The gate is the same everywhere: one false VERIFIED fails the build. Known gap: on the
arm64 macOS runner lief reads the first slice of each universal binary, which is x86_64,
so the arm64 Mach-O slices are not yet exercised.

### Third-party replication: aarch64 Linux ELF (Jetson)

Reported in [#5](https://github.com/2akouwu/reverify/pull/5) by @IMGillusion — 19 aarch64
ELFs from `/usr/bin`:

```
prior wrong (hallucination rate): 19/19 = 100%
false VERIFIED (must be 0)       : 0
true bytes after 1 feedback round: 19/19 = 100%
```

The x86 textbook prior is a weak probe on ARM64 — it is *expected* to be wrong, because
aarch64 entry points open with `sub sp, sp, #N` / `mov x29, sp`. The load-bearing number is
the **zero false-VERIFIED**: the soundness guarantee holds across architectures. Producing
this run surfaced a real bug (arm64 was routed to the x86_64 decoder), fixed in v0.9.1 —
which is what replication is for.

## Reading it honestly

- The meaningful result is the false-VERIFIED row, and the honest way to read "0 of N" is
  the upper bound: 0/71 means the rate is below about 5% with 95% confidence, not that it is
  zero. The bound tightens only with more binaries; CI adds two platforms per push and the
  `--per-dir` knob widens the sample. The zero-false-accept property is the verifier's
  soundness, tested independently (`tests/test_oracle.py`, `test_differential.py`, the
  nightly fuzz) and confirmed here in the field.
- "Prior wrong" is specific to **entry-point** prologues, which are CRT/DLL startup stubs
  with characteristic non-textbook shapes. Random internal functions would give a different
  rate; this is one clean probe of one well-known prior, not a survey of all hallucinations.
- "True bytes after 1 round" shows the feedback loop converging, but round 2 restates what
  the tool reported — in the scored `reconstruct` loop that restatement is echo-detected and
  carries no information weight. It proves the loop reaches ground truth; it is not the
  model independently reasoning.
- Binaries whose entry the verifier cannot judge (no engines, unknown format) are reported
  as *inconclusive* and excluded from every rate — never silently dropped and never counted
  as a pass.

The model in the worked example ([EXAMPLE.md](EXAMPLE.md)) was Claude, plugged in as the
injected proposer — no API key, no specific model. The benchmark itself needs no model at
all: the prior is fixed, so anyone can run it.

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
